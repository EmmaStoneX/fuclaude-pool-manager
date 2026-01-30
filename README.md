# FuClaude Pool Manager Worker

<div align="center">

[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](./LICENSE)
[![Version](https://img.shields.io/badge/Version-0.2.0-blue?style=for-the-badge)](https://github.com/EmmaStoneX/fuclaude-pool-manager)

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/EmmaStoneX/fuclaude-pool-manager)

</div>

If you find this project helpful, please consider giving it a star ⭐️!

This Cloudflare Worker provides a backend service to manage access to Claude AI using a pool of session keys (SKs). It supports OAuth authentication via **LinuxDO** and **GitHub**, allowing users to obtain a Claude login URL by either requesting a specific account or a random available account. It also includes administrative endpoints to manage accounts and users.

- **Frontend Project**: [https://github.com/EmmaStoneX/fuclaude-pool-manager-ui](https://github.com/EmmaStoneX/fuclaude-pool-manager-ui)

## ✨ Features

### Authentication
- **LinuxDO OAuth**: Login with LinuxDO account
- **GitHub OAuth**: Login with GitHub account
- **Session Management**: Secure cookie-based session management
- **User Trust Levels**: Support for LinuxDO trust levels

### User Management (Admin)
- View all registered users from both OAuth providers
- Ban/Unban users
- Filter by provider (LinuxDO/GitHub) and status (active/banned)
- Track login count and last login time

### Account Pool Management
- Add, update, delete email-SK pairs
- Batch operations for bulk management
- Random or specific account allocation

## Quick Start: One-Click Deploy

Click the "Deploy with Cloudflare" button above. The Cloudflare dashboard will guide you through deploying the Worker.

### Step 1: Configure Secrets and Variables

After deployment, navigate to **Workers & Pages** → Your Worker → **Settings** → **Variables** and set:

#### Required Secrets (Type: Secret)
- `ADMIN_PASSWORD` - Admin panel password
- `LINUXDO_CLIENT_SECRET` - LinuxDO OAuth secret
- `GITHUB_CLIENT_SECRET` - GitHub OAuth secret

#### Required Variables
- `LINUXDO_CLIENT_ID` - LinuxDO OAuth client ID
- `LINUXDO_REDIRECT_URI` - LinuxDO callback URL (e.g., `https://your-worker.workers.dev/api/auth/callback/linux-do`)
- `GITHUB_CLIENT_ID` - GitHub OAuth client ID
- `GITHUB_REDIRECT_URI` - GitHub callback URL (e.g., `https://your-worker.workers.dev/api/auth/callback/github`)
- `FRONTEND_URL` - Your frontend URL for redirects
- `BASE_URL` - Your FuClaude mirror base URL

#### Optional Variables
- `TOKEN_EXPIRES_IN` - Default token expiration in seconds (e.g., `86400` for 24 hours)

### Step 2: Initialize Your Data

Add your accounts via the batch API endpoint:

```bash
curl -X POST https://YOUR_WORKER_URL/api/admin/batch \
-H "Content-Type: application/json" \
-d '{
  "admin_password": "YOUR_ADMIN_PASSWORD",
  "actions": [
    { "action": "add", "email": "user1@example.com", "sk": "sk-abc..." },
    { "action": "add", "email": "user2@example.com", "sk": "sk-def..." }
  ]
}'
```

## API Documentation

### Authentication Endpoints

#### OAuth Login Initiation
- **LinuxDO**: `GET /api/auth/login/linux-do`
- **GitHub**: `GET /api/auth/login/github`

#### OAuth Callbacks
- **LinuxDO**: `GET /api/auth/callback/linux-do`
- **GitHub**: `GET /api/auth/callback/github`

#### Session
- **Check Session**: `GET /api/auth/me`
- **Logout**: `POST /api/auth/logout`

### User Endpoints

#### List Available Emails
- **Method**: `GET`
- **Path**: `/api/emails`

#### Login to Claude
- **Method**: `POST`
- **Path**: `/api/login`
- **Body**: `{"mode": "specific" | "random", "email"?: "...", "unique_name"?: "...", "expires_in"?: number}`

### Admin Endpoints

All admin endpoints require `admin_password` in the request body.

#### Account Management
- **List Accounts**: `POST /api/admin/list`
- **Add Account**: `POST /api/admin/add`
- **Update Account**: `POST /api/admin/update`
- **Delete Account**: `POST /api/admin/delete`
- **Batch Operations**: `POST /api/admin/batch`

#### User Management
- **List Users**: `POST /api/admin/users`
- **Ban User**: `POST /api/admin/users/ban`
- **Unban User**: `POST /api/admin/users/unban`

Request body for ban/unban:
```json
{
  "admin_password": "...",
  "user_id": "12345",
  "auth_provider": "linuxdo" | "github"
}
```

## For Developers

### Manual CLI Deployment

1. Clone the repository:
   ```bash
   git clone https://github.com/EmmaStoneX/fuclaude-pool-manager.git
   cd fuclaude-pool-manager
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create KV Namespace:
   ```bash
   npx wrangler kv namespace create "CLAUDE_KV"
   npx wrangler kv namespace create "CLAUDE_KV" --preview
   ```

4. Update `wrangler.jsonc` with the KV namespace IDs.

5. Set secrets:
   ```bash
   npx wrangler secret put ADMIN_PASSWORD
   npx wrangler secret put LINUXDO_CLIENT_SECRET
   npx wrangler secret put GITHUB_CLIENT_SECRET
   ```

6. Deploy:
   ```bash
   npx wrangler deploy
   ```

### Local Development

```bash
npm run dev
```

This starts the local development server at `http://localhost:8787`.

## OAuth Setup Guide

### LinuxDO OAuth

1. Go to LinuxDO developer settings
2. Create a new OAuth application
3. Set the callback URL to: `https://your-worker.workers.dev/api/auth/callback/linux-do`
4. Copy the Client ID and Client Secret

### GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App
3. Set the callback URL to: `https://your-worker.workers.dev/api/auth/callback/github`
4. Copy the Client ID and Client Secret

## Troubleshooting

### "Conversation not found" on first message
This is a known behavior of FuClaude. When entering a new session, click one of the preset prompts (like "Life stuff", "Write", "Code") to start the conversation instead of typing directly.

### OAuth Login Issues
- Ensure all OAuth environment variables are correctly set
- Verify callback URLs match exactly in both OAuth provider settings and worker configuration
- Check that `FRONTEND_URL` is set correctly

## License

This project is licensed under the [MIT License](./LICENSE).

---
Forked from [f14XuanLv/fuclaude-pool-manager](https://github.com/f14XuanLv/fuclaude-pool-manager)