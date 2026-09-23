/**
 * lily-github-mcp-bridge
 *
 * A minimal, zero-dependency, self-hosted MCP server that lets Claude read
 * and WRITE to specific GitHub repositories using a Personal Access Token
 * (PAT) that you control. Built because Anthropic's built-in GitHub
 * connector is read-only for repo contents.
 *
 * - No npm dependencies: uses only Node's built-in http/https/crypto/fs.
 * - OAuth 2.0 (authorization-code style) in front of the MCP endpoint,
 *   gated by an admin secret (MCP_ADMIN_SECRET) you set as an env var.
 *   This satisfies Claude.ai's requirement that custom connectors use OAuth.
 * - Access tokens last 1 hour and are renewed automatically via a
 *   stateless 30-day refresh token, so the connector doesn't need
 *   re-authorizing every hour (and survives server restarts).
 * - The actual GitHub PAT (GITHUB_TOKEN) never leaves this server or touches
 *   Claude / Anthropic infrastructure. It's used only for outbound calls to
 *   api.github.com.
 * - Repo access is restricted to ALLOWED_REPOS (comma-separated "owner/repo"
 *   list, with "owner/*" and "*" wildcards supported) so the bridge can't
 *   touch anything beyond what you intend, even if the PAT itself has
 *   broader scope.
 * - GET /status.html serves a small static status page (no auth required,
 *   read-only, doesn't expose repo contents) that pings /health.
 *
 * Required env vars:
 *   GITHUB_TOKEN     - a GitHub PAT (fine-grained, scoped narrowly is best)
 *   MCP_ADMIN_SECRET - a long random string; acts as the password gating
 *                      the OAuth /authorize page
 *   MCP_BASE_URL     - the public HTTPS URL this server is reachable at,
 *                      e.g. https://your-domain.com  (no trailing slash)
 *   ALLOWED_REPOS    - comma-separated "owner/repo" list, e.g.
 *                      "UmakraftCircle/DmLilyAi". Also accepts "owner/*"
 *                      (every repo under that owner) or "*" (every repo the
 *                      token can reach).
 *
 * Optional env vars:
 *   MCP_JWT_SECRET   - a separate long random string used to sign tokens and
 *                      client IDs. Recommended, so the login password and the
 *                      signing key aren't the same value. Falls back to
 *                      MCP_ADMIN_SECRET if unset. Changing it invalidates
 *                      all issued tokens (you'll need to reconnect).
 *
 * Run:
 *   GITHUB_TOKEN=ghp_xxx MCP_ADMIN_SECRET=xxx MCP_BASE_URL=https://your.host \
 *   ALLOWED_REPOS=UmakraftCircle/DmLilyAi node server.js
 *
 * Then in claude.ai: Settings -> Connectors -> Add custom connector
 *   URL: https://your.host/mcp
 */

'use strict';

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3232;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const ADMIN_SECRET = process.env.MCP_ADMIN_SECRET;
const JWT_SECRET = process.env.MCP_JWT_SECRET || ADMIN_SECRET;
const BASE_URL = (process.env.MCP_BASE_URL || '').replace(/\/$/, '');
const ALLOWED_REPOS = new Set(
  (process.env.ALLOWED_REPOS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
);

const ACCESS_TOKEN_TTL_S = 60 * 60; // 1 hour
const REFRESH_TOKEN_TTL_S = 60 * 60 * 24 * 30; // 30 days

if (!GITHUB_TOKEN) {
  console.error('FATAL: GITHUB_TOKEN env var is required.');
  process.exit(1);
}
if (!ADMIN_SECRET) {
  console.error('FATAL: MCP_ADMIN_SECRET env var is required.');
  process.exit(1);
}
if (!BASE_URL) {
  console.error('FATAL: MCP_BASE_URL env var is required (e.g. https://your.host).');
  process.exit(1);
}
if (ALLOWED_REPOS.size === 0) {
  console.error('FATAL: ALLOWED_REPOS env var is required, e.g. "owner/repo,owner/repo2".');
  process.exit(1);
}
if (!process.env.MCP_JWT_SECRET) {
  console.warn('WARN: MCP_JWT_SECRET is not set; signing tokens with MCP_ADMIN_SECRET. Set a separate value for better isolation.');
}

// In-memory store for OAuth authorization codes (short-lived, single-use).
// Fine for a single-instance bridge server; not meant to scale horizontally.
const pendingCodes = new Map(); // code -> { expiresAt, codeChallenge, codeChallengeMethod, clientId }

// ---------------------------------------------------------------------------
// Static status page (read-only, no auth, doesn't expose repo contents)
// ---------------------------------------------------------------------------

let STATUS_HTML = null;
try {
  STATUS_HTML = fs.readFileSync(path.join(__dirname, 'status.html'), 'utf8');
} catch (e) {
  console.warn('WARN: status.html not found next to server.js; /status.html will 404.');
}

// ---------------------------------------------------------------------------
// Small crypto helpers
// ---------------------------------------------------------------------------

// Constant-time string comparison. Both sides are hashed first so the inputs
// are always the same length (timingSafeEqual throws on length mismatch and
// an early length check would leak the secret's length).
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---------------------------------------------------------------------------
// Tiny JWT (HS256) implementation, no external deps
// ---------------------------------------------------------------------------

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function signJwt(payload, secret, expiresInSeconds) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: now, exp: now + expiresInSeconds };
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(fullPayload));
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `${headerB64}.${payloadB64}.${signature}`;
}

// Returns the payload for a valid, unexpired token, or null for anything
// else (malformed, bad signature, expired). Never throws.
function verifyJwt(token, secret) {
  try {
    const parts = String(token).split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, signature] = parts;
    const expected = crypto
      .createHmac('sha256', secret)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    if (!safeEqual(signature, expected)) return null;
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
    if (!payload || typeof payload !== 'object') return null;
    if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function issueTokens() {
  return {
    access_token: signJwt({ sub: 'lily-mcp-user', typ: 'access' }, JWT_SECRET, ACCESS_TOKEN_TTL_S),
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL_S,
    refresh_token: signJwt({ sub: 'lily-mcp-user', typ: 'refresh' }, JWT_SECRET, REFRESH_TOKEN_TTL_S),
  };
}

// ---------------------------------------------------------------------------
// Stateless OAuth client IDs (RFC 7591 dynamic registration)
//
// The client_id embeds the registered redirect URIs and is HMAC-signed, so we
// can validate redirect_uri on /authorize without keeping registrations in
// memory (which a free-tier restart would wipe out).
// ---------------------------------------------------------------------------

function signClientPayload(p64) {
  return crypto.createHmac('sha256', JWT_SECRET).update(`client.${p64}`).digest('base64url');
}

function makeClientId(redirectUris) {
  const p64 = base64url(JSON.stringify({ ru: redirectUris }));
  return `${p64}.${signClientPayload(p64)}`;
}

function parseClientId(clientId) {
  try {
    const parts = String(clientId).split('.');
    if (parts.length !== 2) return null;
    const [p64, sig] = parts;
    if (!p64 || !sig || !safeEqual(sig, signClientPayload(p64))) return null;
    const p = JSON.parse(Buffer.from(p64, 'base64url').toString('utf8'));
    return p && Array.isArray(p.ru) ? { redirectUris: p.ru } : null;
  } catch (e) {
    return null;
  }
}

// Returns an error string, or null if the client + redirect URI are valid.
function validateAuthRequest(clientId, redirectUri) {
  const client = parseClientId(clientId);
  if (!client) return 'unknown_client';
  if (!redirectUri || !client.redirectUris.includes(redirectUri)) return 'redirect_uri_mismatch';
  return null;
}

function isAcceptableRedirectUri(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol === 'https:') return true;
    // Allow loopback http for native/desktop MCP clients.
    return u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]');
  } catch (e) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Brute-force protection for /authorize
// ---------------------------------------------------------------------------

const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_MAX_FAILS_PER_IP = 5;
const AUTH_MAX_FAILS_GLOBAL = 20; // backstop in case the client IP can be spoofed
const authFailures = new Map(); // ip -> [timestamps]
let globalAuthFailures = [];

function clientIp(req) {
  // Behind a reverse proxy the rightmost X-Forwarded-For entry is the one the
  // proxy itself appended; earlier entries can be forged by the client.
  const xff = String(req.headers['x-forwarded-for'] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return xff.length ? xff[xff.length - 1] : (req.socket && req.socket.remoteAddress) || 'unknown';
}

function recent(list) {
  const cutoff = Date.now() - AUTH_WINDOW_MS;
  return list.filter((t) => t > cutoff);
}

function authLockedOut(ip) {
  globalAuthFailures = recent(globalAuthFailures);
  const mine = recent(authFailures.get(ip) || []);
  if (mine.length) authFailures.set(ip, mine);
  else authFailures.delete(ip);
  return mine.length >= AUTH_MAX_FAILS_PER_IP || globalAuthFailures.length >= AUTH_MAX_FAILS_GLOBAL;
}

function recordAuthFailure(ip) {
  const now = Date.now();
  authFailures.set(ip, [...recent(authFailures.get(ip) || []), now]);
  globalAuthFailures.push(now);
}

// Periodically drop stale entries so the map can't grow without bound.
setInterval(() => {
  for (const [ip, list] of authFailures) {
    const r = recent(list);
    if (r.length) authFailures.set(ip, r);
    else authFailures.delete(ip);
  }
}, AUTH_WINDOW_MS).unref();

// ---------------------------------------------------------------------------
// GitHub REST API helper
// ---------------------------------------------------------------------------

function githubRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request(
      {
        hostname: 'api.github.com',
        path,
        method,
        headers: {
          'User-Agent': 'lily-github-mcp-bridge',
          Authorization: `Bearer ${GITHUB_TOKEN}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          let parsed = null;
          try {
            parsed = raw ? JSON.parse(raw) : null;
          } catch (e) {
            parsed = raw;
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function assertRepoAllowed(owner, repo) {
  const key = `${owner}/${repo}`;
  // Exact "owner/repo" match, org-wide "owner/*" match, or global "*" match.
  const allowed =
    ALLOWED_REPOS.has(key) ||
    ALLOWED_REPOS.has(`${owner}/*`) ||
    ALLOWED_REPOS.has('*');
  if (!allowed) {
    const err = new Error(`Repo "${key}" is not in ALLOWED_REPOS for this bridge.`);
    err.isToolError = true;
    throw err;
  }
}

// Encode a repo file path for use in a GitHub contents API URL. Each segment
// is encoded on its own so "/" separators are preserved (encoding the whole
// path would turn "src/foo.js" into "src%2Ffoo.js", which GitHub rejects).
// Leading/trailing slashes are stripped; an empty path means the repo root.
function encodePath(p) {
  return String(p || '')
    .split('/')
    .filter(Boolean)
    .map(encodeURIComponent)
    .join('/');
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

const TOOLS = [
  {
    name: 'get_file_contents',
    description:
      'Get the contents and blob SHA of a file in an allowed repo. If the path is a directory (or empty for the repo root), returns a listing of its entries instead.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        path: { type: 'string', description: 'File or directory path. Use an empty string for the repo root.' },
        ref: { type: 'string', description: 'Branch, tag or SHA. Defaults to the repo default branch.' },
      },
      required: ['owner', 'repo', 'path'],
    },
    handler: async ({ owner, repo, path: p, ref }) => {
      assertRepoAllowed(owner, repo);
      const q = ref ? `?ref=${encodeURIComponent(ref)}` : '';
      const res = await githubRequest('GET', `/repos/${owner}/${repo}/contents/${encodePath(p)}${q}`);
      if (res.status >= 400) throw new Error(`GitHub error ${res.status}: ${JSON.stringify(res.body)}`);

      // Directory: GitHub returns an array of entries.
      if (Array.isArray(res.body)) {
        return {
          path: p || '/',
          type: 'dir',
          entries: res.body.map((e) => ({
            name: e.name,
            path: e.path,
            type: e.type,
            sha: e.sha,
            size: e.size,
          })),
        };
      }

      const content = res.body.encoding === 'base64' ? Buffer.from(res.body.content, 'base64').toString('utf8') : res.body.content;
      return { sha: res.body.sha, path: res.body.path, content };
    },
  },
  {
    name: 'create_or_update_file',
    description: 'Create or update a single file with one commit. Pass sha when updating an existing file.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        path: { type: 'string' },
        content: { type: 'string', description: 'Raw file content, not base64-encoded.' },
        message: { type: 'string' },
        branch: { type: 'string' },
        sha: { type: 'string', description: 'Required when overwriting an existing file.' },
      },
      required: ['owner', 'repo', 'path', 'content', 'message', 'branch'],
    },
    handler: async ({ owner, repo, path: p, content, message, branch, sha }) => {
      assertRepoAllowed(owner, repo);
      const body = {
        message,
        branch,
        content: Buffer.from(content, 'utf8').toString('base64'),
        ...(sha ? { sha } : {}),
      };
      const res = await githubRequest('PUT', `/repos/${owner}/${repo}/contents/${encodePath(p)}`, body);
      if (res.status >= 400) throw new Error(`GitHub error ${res.status}: ${JSON.stringify(res.body)}`);
      return { commit: res.body.commit && res.body.commit.sha, path: p };
    },
  },
  {
    name: 'delete_file',
    description: 'Delete a file from a repo.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        path: { type: 'string' },
        message: { type: 'string' },
        branch: { type: 'string' },
        sha: { type: 'string', description: 'Current blob SHA of the file (get via get_file_contents).' },
      },
      required: ['owner', 'repo', 'path', 'message', 'branch', 'sha'],
    },
    handler: async ({ owner, repo, path: p, message, branch, sha }) => {
      assertRepoAllowed(owner, repo);
      const res = await githubRequest('DELETE', `/repos/${owner}/${repo}/contents/${encodePath(p)}`, {
        message,
        branch,
        sha,
      });
      if (res.status >= 400) throw new Error(`GitHub error ${res.status}: ${JSON.stringify(res.body)}`);
      return { deleted: p };
    },
  },
  {
    name: 'list_branches',
    description: 'List branches in a repo.',
    inputSchema: {
      type: 'object',
      properties: { owner: { type: 'string' }, repo: { type: 'string' } },
      required: ['owner', 'repo'],
    },
    handler: async ({ owner, repo }) => {
      assertRepoAllowed(owner, repo);
      const res = await githubRequest('GET', `/repos/${owner}/${repo}/branches`);
      if (res.status >= 400) throw new Error(`GitHub error ${res.status}: ${JSON.stringify(res.body)}`);
      return res.body.map((b) => ({ name: b.name, sha: b.commit && b.commit.sha }));
    },
  },
  {
    name: 'create_branch',
    description: 'Create a new branch from an existing branch (defaults to the repo default branch).',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        branch: { type: 'string' },
        from_branch: { type: 'string' },
      },
      required: ['owner', 'repo', 'branch'],
    },
    handler: async ({ owner, repo, branch, from_branch }) => {
      assertRepoAllowed(owner, repo);
      let base = from_branch;
      if (!base) {
        const repoRes = await githubRequest('GET', `/repos/${owner}/${repo}`);
        if (repoRes.status >= 400) throw new Error(`GitHub error ${repoRes.status}: ${JSON.stringify(repoRes.body)}`);
        base = repoRes.body.default_branch;
      }
      const refRes = await githubRequest('GET', `/repos/${owner}/${repo}/git/ref/heads/${encodeURIComponent(base)}`);
      if (refRes.status >= 400) throw new Error(`GitHub error ${refRes.status}: ${JSON.stringify(refRes.body)}`);
      const sha = refRes.body.object.sha;
      const createRes = await githubRequest('POST', `/repos/${owner}/${repo}/git/refs`, {
        ref: `refs/heads/${branch}`,
        sha,
      });
      if (createRes.status >= 400) throw new Error(`GitHub error ${createRes.status}: ${JSON.stringify(createRes.body)}`);
      return { branch, from: base, sha };
    },
  },
  {
    name: 'push_files',
    description: 'Commit multiple files at once (atomic single commit) using the git trees API.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        branch: { type: 'string' },
        message: { type: 'string' },
        files: {
          type: 'array',
          items: {
            type: 'object',
            properties: { path: { type: 'string' }, content: { type: 'string' } },
            required: ['path', 'content'],
          },
        },
      },
      required: ['owner', 'repo', 'branch', 'message', 'files'],
    },
    handler: async ({ owner, repo, branch, message, files }) => {
      assertRepoAllowed(owner, repo);
      const refRes = await githubRequest('GET', `/repos/${owner}/${repo}/git/ref/heads/${encodeURIComponent(branch)}`);
      if (refRes.status >= 400) throw new Error(`GitHub error ${refRes.status}: ${JSON.stringify(refRes.body)}`);
      const baseCommitSha = refRes.body.object.sha;

      const commitRes = await githubRequest('GET', `/repos/${owner}/${repo}/git/commits/${baseCommitSha}`);
      if (commitRes.status >= 400) throw new Error(`GitHub error ${commitRes.status}: ${JSON.stringify(commitRes.body)}`);
      const baseTreeSha = commitRes.body.tree.sha;

      const blobs = [];
      for (const f of files) {
        const blobRes = await githubRequest('POST', `/repos/${owner}/${repo}/git/blobs`, {
          content: Buffer.from(f.content, 'utf8').toString('base64'),
          encoding: 'base64',
        });
        if (blobRes.status >= 400) throw new Error(`GitHub error ${blobRes.status}: ${JSON.stringify(blobRes.body)}`);
        blobs.push({ path: f.path, mode: '100644', type: 'blob', sha: blobRes.body.sha });
      }

      const treeRes = await githubRequest('POST', `/repos/${owner}/${repo}/git/trees`, {
        base_tree: baseTreeSha,
        tree: blobs,
      });
      if (treeRes.status >= 400) throw new Error(`GitHub error ${treeRes.status}: ${JSON.stringify(treeRes.body)}`);

      const newCommitRes = await githubRequest('POST', `/repos/${owner}/${repo}/git/commits`, {
        message,
        tree: treeRes.body.sha,
        parents: [baseCommitSha],
      });
      if (newCommitRes.status >= 400) throw new Error(`GitHub error ${newCommitRes.status}: ${JSON.stringify(newCommitRes.body)}`);

      const updateRefRes = await githubRequest('PATCH', `/repos/${owner}/${repo}/git/refs/heads/${encodeURIComponent(branch)}`, {
        sha: newCommitRes.body.sha,
      });
      if (updateRefRes.status >= 400) throw new Error(`GitHub error ${updateRefRes.status}: ${JSON.stringify(updateRefRes.body)}`);

      return { commit: newCommitRes.body.sha, filesCommitted: files.map((f) => f.path) };
    },
  },
];

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function sendJson(res, status, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    ...(extraHeaders || {}),
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function getBearerToken(req) {
  const auth = req.headers['authorization'] || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

// ---------------------------------------------------------------------------
// OAuth 2.0 endpoints (authorization code flow, gated by MCP_ADMIN_SECRET)
// ---------------------------------------------------------------------------

function handleAuthServerMetadata(req, res) {
  sendJson(res, 200, {
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/token`,
    registration_endpoint: `${BASE_URL}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
  });
}

// RFC 9728 - tells an MCP client which authorization server protects this
// resource. Claude fetches this (per the URL in the WWW-Authenticate header
// on a 401 from /mcp) before it knows where to send the user to sign in.
function handleProtectedResourceMetadata(req, res) {
  sendJson(res, 200, {
    resource: `${BASE_URL}/mcp`,
    authorization_servers: [BASE_URL],
  });
}

// RFC 7591 - Dynamic Client Registration. claude.ai has no pre-shared
// client_id for a server it's never seen before, so it registers itself
// here first. The returned client_id is a signed token that embeds the
// registered redirect URIs (see makeClientId); no client_secret is issued
// since this is a public client using PKCE.
async function handleRegister(req, res) {
  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch (e) {
    sendJson(res, 400, { error: 'invalid_client_metadata' });
    return;
  }

  const uris = payload && payload.redirect_uris;
  if (
    !Array.isArray(uris) ||
    uris.length === 0 ||
    uris.length > 10 ||
    !uris.every((u) => typeof u === 'string' && isAcceptableRedirectUri(u))
  ) {
    sendJson(res, 400, {
      error: 'invalid_redirect_uri',
      error_description: 'redirect_uris must be 1-10 https (or loopback http) URLs.',
    });
    return;
  }

  sendJson(res, 201, {
    client_id: makeClientId(uris),
    redirect_uris: uris,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
  });
}

function handleAuthorizeGet(req, res, query) {
  const redirectUri = query.get('redirect_uri') || '';
  const state = query.get('state') || '';
  const clientId = query.get('client_id') || '';
  const codeChallenge = query.get('code_challenge') || '';
  const codeChallengeMethod = query.get('code_challenge_method') || '';

  // Reject bad requests before ever showing the password form.
  const invalid = validateAuthRequest(clientId, redirectUri);
  if (invalid) {
    sendJson(res, 400, { error: 'invalid_request', error_description: invalid });
    return;
  }

  const html = `<!doctype html>
<html><head><meta charset="utf-8"><title>lily-github-mcp-bridge</title>
<style>body{font-family:system-ui,sans-serif;max-width:420px;margin:80px auto;padding:0 16px}
input{width:100%;padding:10px;margin:8px 0;box-sizing:border-box}
button{padding:10px 16px;cursor:pointer}</style></head>
<body>
<h2>Authorize MCP access</h2>
<p>Enter the admin secret to authorize this connection.</p>
<form method="POST" action="/authorize">
  <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
  <input type="hidden" name="state" value="${escapeHtml(state)}">
  <input type="hidden" name="client_id" value="${escapeHtml(clientId)}">
  <input type="hidden" name="code_challenge" value="${escapeHtml(codeChallenge)}">
  <input type="hidden" name="code_challenge_method" value="${escapeHtml(codeChallengeMethod)}">
  <input type="password" name="secret" placeholder="Admin secret" required autofocus>
  <button type="submit">Authorize</button>
</form>
</body></html>`;
  res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': Buffer.byteLength(html) });
  res.end(html);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function handleAuthorizePost(req, res) {
  const ip = clientIp(req);
  if (authLockedOut(ip)) {
    res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': String(Math.ceil(AUTH_WINDOW_MS / 1000)) });
    res.end(JSON.stringify({ error: 'too_many_attempts' }));
    return;
  }

  const raw = await readBody(req);
  const params = new URLSearchParams(raw);
  const secret = params.get('secret') || '';
  const redirectUri = params.get('redirect_uri') || '';
  const state = params.get('state') || '';
  const clientId = params.get('client_id') || '';
  const codeChallenge = params.get('code_challenge') || '';
  const codeChallengeMethod = params.get('code_challenge_method') || 'plain';

  const invalid = validateAuthRequest(clientId, redirectUri);
  if (invalid) {
    sendJson(res, 400, { error: 'invalid_request', error_description: invalid });
    return;
  }

  if (!safeEqual(secret, ADMIN_SECRET)) {
    recordAuthFailure(ip);
    sendJson(res, 401, { error: 'invalid_secret' });
    return;
  }
  authFailures.delete(ip);

  const code = crypto.randomBytes(24).toString('hex');
  pendingCodes.set(code, {
    expiresAt: Date.now() + 5 * 60 * 1000,
    codeChallenge,
    codeChallengeMethod,
    clientId,
  });

  const location = new URL(redirectUri);
  location.searchParams.set('code', code);
  if (state) location.searchParams.set('state', state);

  res.writeHead(302, { Location: location.toString() });
  res.end();
}

function verifyPkce(entry, codeVerifier) {
  if (!entry.codeChallenge) return true; // client didn't use PKCE
  if (!codeVerifier) return false;
  if (entry.codeChallengeMethod === 'S256') {
    const hash = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    return safeEqual(hash, entry.codeChallenge);
  }
  // 'plain'
  return safeEqual(codeVerifier, entry.codeChallenge);
}

async function handleToken(req, res) {
  const raw = await readBody(req);
  const params = new URLSearchParams(raw);
  const grantType = params.get('grant_type');

  if (grantType === 'refresh_token') {
    const claims = verifyJwt(params.get('refresh_token') || '', JWT_SECRET);
    if (!claims || claims.typ !== 'refresh') {
      sendJson(res, 400, { error: 'invalid_grant' });
      return;
    }
    sendJson(res, 200, issueTokens());
    return;
  }

  if (grantType !== 'authorization_code') {
    sendJson(res, 400, { error: 'unsupported_grant_type' });
    return;
  }

  const code = params.get('code');
  const entry = code && pendingCodes.get(code);
  if (!entry || Date.now() > entry.expiresAt) {
    sendJson(res, 400, { error: 'invalid_grant' });
    return;
  }

  const codeVerifier = params.get('code_verifier');
  if (!verifyPkce(entry, codeVerifier)) {
    sendJson(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
    return;
  }

  pendingCodes.delete(code); // single-use

  sendJson(res, 200, issueTokens());
}

// ---------------------------------------------------------------------------
// MCP JSON-RPC endpoint
// ---------------------------------------------------------------------------

async function handleMcp(req, res) {
  const token = getBearerToken(req);
  const claims = token ? verifyJwt(token, JWT_SECRET) : null;
  // Refresh tokens must never be usable as access tokens.
  if (!claims || claims.typ === 'refresh') {
    // Point the client at our protected-resource metadata so it knows
    // where to go to authenticate (required for MCP OAuth discovery).
    res.writeHead(401, {
      'Content-Type': 'application/json',
      'WWW-Authenticate': `Bearer resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource"`,
    });
    res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Unauthorized' }, id: null }));
    return;
  }

  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch (e) {
    sendJson(res, 400, { jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' }, id: null });
    return;
  }

  const { id, method, params } = payload;

  try {
    if (method === 'initialize') {
      sendJson(res, 200, {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'lily-github-mcp-bridge', version: '1.1.0' },
        },
      });
      return;
    }

    if (method === 'tools/list') {
      sendJson(res, 200, {
        jsonrpc: '2.0',
        id,
        result: { tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) },
      });
      return;
    }

    if (method === 'tools/call') {
      const tool = TOOLS.find((t) => t.name === params.name);
      if (!tool) {
        sendJson(res, 200, { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${params.name}` } });
        return;
      }
      try {
        const result = await tool.handler(params.arguments || {});
        sendJson(res, 200, {
          jsonrpc: '2.0',
          id,
          result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] },
        });
      } catch (err) {
        sendJson(res, 200, {
          jsonrpc: '2.0',
          id,
          result: { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true },
        });
      }
      return;
    }

    sendJson(res, 200, { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown method: ${method}` } });
  } catch (err) {
    sendJson(res, 500, { jsonrpc: '2.0', id, error: { code: -32000, message: err.message } });
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (url.pathname === '/health' && req.method === 'GET') {
      // CORS enabled so the /status.html page (or any browser page) can read
      // this. It returns no repo data or secrets, so an open CORS policy
      // here is safe.
      sendJson(res, 200, { status: 'ok' }, { 'Access-Control-Allow-Origin': '*' });
      return;
    }
    if (url.pathname === '/status.html' && req.method === 'GET') {
      if (!STATUS_HTML) {
        sendJson(res, 404, { error: 'not_found' });
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': Buffer.byteLength(STATUS_HTML) });
      res.end(STATUS_HTML);
      return;
    }
    if (url.pathname === '/.well-known/oauth-authorization-server' && req.method === 'GET') {
      handleAuthServerMetadata(req, res);
      return;
    }
    if (url.pathname === '/.well-known/oauth-protected-resource' && req.method === 'GET') {
      handleProtectedResourceMetadata(req, res);
      return;
    }
    if (url.pathname === '/register' && req.method === 'POST') {
      await handleRegister(req, res);
      return;
    }
    if (url.pathname === '/authorize' && req.method === 'GET') {
      handleAuthorizeGet(req, res, url.searchParams);
      return;
    }
    if (url.pathname === '/authorize' && req.method === 'POST') {
      await handleAuthorizePost(req, res);
      return;
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      await handleToken(req, res);
      return;
    }
    if (url.pathname === '/mcp' && req.method === 'POST') {
      await handleMcp(req, res);
      return;
    }
    sendJson(res, 404, { error: 'not_found' });
  } catch (err) {
    sendJson(res, 500, { error: 'internal_error', message: err.message });
  }
});

server.listen(PORT, () => {
  console.log(`lily-github-mcp-bridge listening on :${PORT}`);
  console.log(`Allowed repos: ${[...ALLOWED_REPOS].join(', ')}`);
  console.log(`MCP endpoint (once deployed): ${BASE_URL}/mcp`);
});

// ---------------------------------------------------------------------------
// Self-ping — keeps a Render free-tier web service from spinning down after
// its inactivity timeout. Hits our own public /health endpoint on a timer.
// Set SELF_PING=false to disable (e.g. if you're on a paid "Always On" plan).
// ---------------------------------------------------------------------------

const SELF_PING_INTERVAL_MS = Number(process.env.SELF_PING_INTERVAL_MS || 10 * 60 * 1000); // 10 min

function selfPing() {
  https
    .get(`${BASE_URL}/health`, (res) => {
      res.resume(); // drain response body, don't hold the socket open
      console.log(`[self-ping] ${res.statusCode} at ${new Date().toISOString()}`);
    })
    .on('error', (err) => {
      console.error(`[self-ping] failed: ${err.message}`);
    });
}

if (process.env.SELF_PING !== 'false') {
  setInterval(selfPing, SELF_PING_INTERVAL_MS).unref();
  console.log(`Self-ping enabled: pinging ${BASE_URL}/health every ${SELF_PING_INTERVAL_MS / 1000}s`);
}
