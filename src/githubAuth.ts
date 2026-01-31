// src/githubAuth.ts
// GitHub OAuth Authentication Module

/**
 * GitHub OAuth Configuration
 */
interface GitHubOAuthConfig {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    frontendUrl: string;
    adminWhitelist?: string[]; // Admin usernames allowed during maintenance
}

/**
 * GitHub User Data from API
 */
interface GitHubUser {
    id: number;
    login: string;
    name?: string;
    avatar_url?: string;
    email?: string;
}

/**
 * Session Data stored in KV
 */
interface SessionData {
    user_id: number;
    username: string;
    avatar_url?: string;
    auth_provider: 'github' | 'linuxdo';
    created_at: string;
    expires_at: string;
}

/**
 * Stored User Data in KV
 */
interface StoredGitHubUser {
    id: number;
    username: string;
    name?: string;
    avatar_url?: string;
    email?: string;
    first_login: string;
    last_login: string;
    login_count: number;
}

/**
 * Handle GitHub OAuth login redirect
 */
export function handleGitHubOAuthLogin(config: GitHubOAuthConfig): Response {
    const state = crypto.randomUUID();
    const authUrl = new URL('https://github.com/login/oauth/authorize');
    authUrl.searchParams.set('client_id', config.clientId);
    authUrl.searchParams.set('redirect_uri', config.redirectUri);
    authUrl.searchParams.set('scope', 'read:user user:email');
    authUrl.searchParams.set('state', state);

    const headers = new Headers({
        'Location': authUrl.toString(),
        'Set-Cookie': `github_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
    });

    return new Response(null, { status: 302, headers });
}

/**
 * Handle GitHub OAuth callback
 */
export async function handleGitHubOAuthCallback(
    request: Request,
    config: GitHubOAuthConfig,
    kv: KVNamespace
): Promise<Response> {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const errorParam = url.searchParams.get('error');

    if (errorParam) {
        return Response.redirect(`${config.frontendUrl}?error=${encodeURIComponent(errorParam)}`, 302);
    }

    if (!code) {
        return Response.redirect(`${config.frontendUrl}?error=missing_code`, 302);
    }

    // Verify state from cookie
    const cookies = request.headers.get('Cookie') || '';
    const stateCookie = cookies.split(';').find(c => c.trim().startsWith('github_oauth_state='));
    const storedState = stateCookie?.split('=')[1]?.trim();

    if (!storedState || storedState !== state) {
        return Response.redirect(`${config.frontendUrl}?error=invalid_state`, 302);
    }

    try {
        // Exchange code for access token
        const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                client_id: config.clientId,
                client_secret: config.clientSecret,
                code: code,
                redirect_uri: config.redirectUri,
            }),
        });

        if (!tokenResponse.ok) {
            const errText = await tokenResponse.text();
            console.error('GitHub token exchange failed:', errText);
            return Response.redirect(`${config.frontendUrl}?error=token_exchange_failed`, 302);
        }

        const tokenData = await tokenResponse.json() as { access_token?: string; error?: string };

        if (tokenData.error || !tokenData.access_token) {
            console.error('GitHub token error:', tokenData.error);
            return Response.redirect(`${config.frontendUrl}?error=${encodeURIComponent(tokenData.error || 'no_access_token')}`, 302);
        }

        const accessToken = tokenData.access_token;

        // Fetch user info from GitHub
        const userResponse = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'FuClaude-Pool-Manager'
            },
        });

        if (!userResponse.ok) {
            console.error('GitHub user fetch failed:', await userResponse.text());
            return Response.redirect(`${config.frontendUrl}?error=user_fetch_failed`, 302);
        }

        const userData = await userResponse.json() as GitHubUser;

        // Check if user is banned (using GitHub user ID with 'github_' prefix to differentiate)
        const bannedUsersStr = await kv.get('BANNED_GITHUB_USERS');
        const bannedUsers: number[] = bannedUsersStr ? JSON.parse(bannedUsersStr) : [];

        if (bannedUsers.includes(userData.id)) {
            return Response.redirect(`${config.frontendUrl}?error=user_banned`, 302);
        }

        // Check if GitHub login is enabled (System Maintenance)
        const settingsStr = await kv.get('SYSTEM_SETTINGS');
        const settings = settingsStr ? JSON.parse(settingsStr) : { login_github_enabled: true };

        if (settings.login_github_enabled === false) {
            // Allow admin whitelist bypass (from config or default)
            const allowedAdmins = config.adminWhitelist || ['EmmaStoneX'];
            if (!allowedAdmins.includes(userData.login)) {
                return Response.redirect(`${config.frontendUrl}?error=maintenance_mode`, 302);
            }
        }


        // Store/update user info
        const usersStr = await kv.get('GITHUB_USERS');
        const users: Record<string, StoredGitHubUser> = usersStr ? JSON.parse(usersStr) : {};

        const now = new Date().toISOString();
        const existingUser = users[String(userData.id)];

        users[String(userData.id)] = {
            id: userData.id,
            username: userData.login,
            name: userData.name,
            avatar_url: userData.avatar_url,
            email: userData.email,
            first_login: existingUser?.first_login || now,
            last_login: now,
            login_count: (existingUser?.login_count || 0) + 1,
        };

        await kv.put('GITHUB_USERS', JSON.stringify(users));

        // Create session token
        const sessionToken = crypto.randomUUID();
        const sessionData: SessionData = {
            user_id: userData.id,
            username: userData.login,
            avatar_url: userData.avatar_url,
            auth_provider: 'github',
            created_at: now,
            expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        };

        await kv.put(`SESSION_${sessionToken}`, JSON.stringify(sessionData), {
            expirationTtl: 7 * 24 * 60 * 60,
        });

        // Set session cookie and redirect to frontend
        const headers = new Headers({
            'Location': config.frontendUrl,
        });
        headers.append('Set-Cookie', `session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${7 * 24 * 60 * 60}`);
        headers.append('Set-Cookie', 'github_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');

        return new Response(null, { status: 302, headers });

    } catch (err) {
        console.error('GitHub OAuth callback error:', err);
        return Response.redirect(`${config.frontendUrl}?error=internal_error`, 302);
    }
}

/**
 * Get all GitHub users (admin only)
 */
export async function getGitHubUsers(kv: KVNamespace): Promise<Record<string, StoredGitHubUser>> {
    const usersStr = await kv.get('GITHUB_USERS');
    return usersStr ? JSON.parse(usersStr) : {};
}

/**
 * Ban a GitHub user
 */
export async function banGitHubUser(userId: number, kv: KVNamespace): Promise<void> {
    const bannedUsersStr = await kv.get('BANNED_GITHUB_USERS');
    const bannedUsers: number[] = bannedUsersStr ? JSON.parse(bannedUsersStr) : [];

    if (!bannedUsers.includes(userId)) {
        bannedUsers.push(userId);
        await kv.put('BANNED_GITHUB_USERS', JSON.stringify(bannedUsers));
    }
}

/**
 * Unban a GitHub user
 */
export async function unbanGitHubUser(userId: number, kv: KVNamespace): Promise<void> {
    const bannedUsersStr = await kv.get('BANNED_GITHUB_USERS');
    const bannedUsers: number[] = bannedUsersStr ? JSON.parse(bannedUsersStr) : [];

    const index = bannedUsers.indexOf(userId);
    if (index > -1) {
        bannedUsers.splice(index, 1);
        await kv.put('BANNED_GITHUB_USERS', JSON.stringify(bannedUsers));
    }
}

/**
 * Get banned GitHub users list
 */
export async function getBannedGitHubUsers(kv: KVNamespace): Promise<number[]> {
    const bannedUsersStr = await kv.get('BANNED_GITHUB_USERS');
    return bannedUsersStr ? JSON.parse(bannedUsersStr) : [];
}
