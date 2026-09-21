# lily-github-mcp-bridge

A minimal, zero-dependency, self-hosted MCP server that gives Claude
**read and write** access to specific GitHub repositories, using a
Personal Access Token (PAT) you control.

Built because Anthropic's built-in GitHub connector only grants
read/metadata access to repo contents — no delete, no commit, no push.

## How it works

- You run this server somewhere reachable over HTTPS (a VPS, a container
  host, etc. — your choice).
- It holds your GitHub PAT as a server-side environment variable. The PAT
  never touches Claude or Anthropic's infrastructure.
- It exposes an MCP endpoint (`/mcp`) with 6 tools: `get_file_contents`,
  `create_or_update_file`, `delete_file`, `list_branches`, `create_branch`,
  and `push_files` (atomic multi-file commits).
- It's gated by a simple OAuth 2.0 flow (required for claude.ai custom
  connectors) protected by an admin secret you set — think of it as a
  password only you know.
- Every tool call is restricted to the repos listed in `ALLOWED_REPOS`,
  even if your PAT has broader access.

## Setup

### 1. Generate a GitHub PAT

GitHub → Settings → Developer settings → Personal access tokens →
Fine-grained tokens → Generate new token.

- Scope it to only the repo(s) you need (e.g. `DmLilyAi`).
- Permissions: **Contents: Read and write** (add **Pull requests: Read and
  write** too if you want PR tools later).

### 2. Generate an admin secret

```bash
openssl rand -hex 32
```

Keep this private — it's effectively the password for this server.

### 3. Configure environment variables

Copy `.env.example` to `.env` (or set these directly in your hosting
platform's environment/secrets panel — never commit real values):

```
GITHUB_TOKEN=<your PAT>
MCP_ADMIN_SECRET=<the random string from step 2>
MCP_BASE_URL=https://<your-deployed-domain>
ALLOWED_REPOS=UmakraftCircle/DmLilyAi
```

### 4. Deploy

Any host that can run `node server.js` and terminate HTTPS works:

```bash
npm install   # no-op, zero dependencies, but keeps tooling happy
npm start
```

Put it behind a reverse proxy (Caddy, nginx, your platform's built-in TLS)
so it's served over HTTPS at `MCP_BASE_URL`.

### 5. Connect it in claude.ai

1. Go to `claude.ai/settings/connectors`.
2. Click **Add custom connector**.
3. Enter the URL: `https://<your-domain>/mcp`.
4. Claude will redirect to this server's `/authorize` page — enter your
   admin secret to approve the connection.

Once connected, Claude can call `get_file_contents`,
`create_or_update_file`, `delete_file`, `list_branches`, `create_branch`,
and `push_files` against any repo listed in `ALLOWED_REPOS`.

## Security notes

- Treat `MCP_ADMIN_SECRET` and `GITHUB_TOKEN` as you would any production
  secret: never commit them, never paste them into a chat, rotate them if
  you suspect exposure.
- The OAuth token this server issues is short-lived (1 hour) and only
  usable against this server's own `/mcp` endpoint — it carries no GitHub
  permissions on its own; the PAT stays server-side.
- Consider narrowing `ALLOWED_REPOS` to exactly what you need, and using a
  fine-grained (not classic) PAT so a leak has a small blast radius.
