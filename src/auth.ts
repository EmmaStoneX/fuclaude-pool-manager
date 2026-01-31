// src/auth.ts
// LinuxDO OAuth Authentication Module

/**
 * LinuxDO OAuth Configuration
 */
interface OAuthConfig {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    frontendUrl: string;
}

/**
 * LinuxDO User Data
 */
interface LinuxDoUser {
    id: number;
    username: string;
    name?: string;
    avatar_template?: string;
    trust_level?: number;
}

/**
 * Session Data stored in KV
 */
interface SessionData {
    user_id: number;
    username: string;
    avatar_url?: string;
    created_at: string;
    expires_at: string;
}

/**
 * Stored User Data in KV
 */
interface StoredUser {
    id: number;
    username: string;
    name?: string;
    avatar_url?: string;
    trust_level?: number;
    first_login: string;
    last_login: string;
    login_count: number;
}

/**
 * Handle OAuth login redirect
 */
export function handleOAuthLogin(config: OAuthConfig): Response {
    const state = crypto.randomUUID();
    const authUrl = new URL('https://connect.linux.do/oauth2/authorize');
    authUrl.searchParams.set('client_id', config.clientId);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('redirect_uri', config.redirectUri);
    authUrl.searchParams.set('state', state);

    const headers = new Headers({
        'Location': authUrl.toString(),
        'Set-Cookie': `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
    });

    return new Response(null, { status: 302, headers });
}

/**
 * Handle OAuth callback
 */
export async function handleOAuthCallback(
    request: Request,
    config: OAuthConfig,
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
    const stateCookie = cookies.split(';').find(c => c.trim().startsWith('oauth_state='));
    const storedState = stateCookie?.split('=')[1]?.trim();

    if (!storedState || storedState !== state) {
        return Response.redirect(`${config.frontendUrl}?error=invalid_state`, 302);
    }

    try {
        // Exchange code for token
        const tokenResponse = await fetch('https://connect.linux.do/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: config.clientId,
                client_secret: config.clientSecret,
                code: code,
                redirect_uri: config.redirectUri,
            }),
        });

        if (!tokenResponse.ok) {
            const errText = await tokenResponse.text();
            console.error('Token exchange failed:', errText);
            return Response.redirect(`${config.frontendUrl}?error=token_exchange_failed`, 302);
        }

        const tokenData = await tokenResponse.json() as { access_token: string };
        const accessToken = tokenData.access_token;

        // Fetch user info
        const userResponse = await fetch('https://connect.linux.do/api/user', {
            headers: { 'Authorization': `Bearer ${accessToken}` },
        });

        if (!userResponse.ok) {
            return Response.redirect(`${config.frontendUrl}?error=user_fetch_failed`, 302);
        }

        const userData = await userResponse.json() as LinuxDoUser;

        // Check if user is banned
        const bannedUsersStr = await kv.get('BANNED_USERS');
        const bannedUsers: number[] = bannedUsersStr ? JSON.parse(bannedUsersStr) : [];

        if (bannedUsers.includes(userData.id)) {
            return Response.redirect(`${config.frontendUrl}?error=user_banned`, 302);
        }

        // Check if LinuxDO login is enabled (System Maintenance)
        const settingsStr = await kv.get('SYSTEM_SETTINGS');
        const settings = settingsStr ? JSON.parse(settingsStr) : { login_linuxdo_enabled: true };

        if (settings.login_linuxdo_enabled === false) {
            // Allow admin whitelist bypass
            const ALLOWED_ADMINS = ['Triceratops2017'];
            if (!ALLOWED_ADMINS.includes(userData.username)) {
                return Response.redirect(`${config.frontendUrl}?error=maintenance_mode`, 302);
            }
        }


        // Store/update user info
        const usersStr = await kv.get('LINUXDO_USERS');
        const users: Record<string, StoredUser> = usersStr ? JSON.parse(usersStr) : {};

        const now = new Date().toISOString();
        const existingUser = users[String(userData.id)];
        const avatarUrl = userData.avatar_template?.replace('{size}', '120');

        users[String(userData.id)] = {
            id: userData.id,
            username: userData.username,
            name: userData.name,
            avatar_url: avatarUrl,
            trust_level: userData.trust_level,
            first_login: existingUser?.first_login || now,
            last_login: now,
            login_count: (existingUser?.login_count || 0) + 1,
        };

        await kv.put('LINUXDO_USERS', JSON.stringify(users));

        // Create session token
        const sessionToken = crypto.randomUUID();
        const sessionData: SessionData = {
            user_id: userData.id,
            username: userData.username,
            avatar_url: avatarUrl,
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
        headers.append('Set-Cookie', 'oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');

        return new Response(null, { status: 302, headers });

    } catch (err) {
        console.error('OAuth callback error:', err);
        return Response.redirect(`${config.frontendUrl}?error=internal_error`, 302);
    }
}

/**
 * Get current user from session
 */
export async function getCurrentUser(
    request: Request,
    kv: KVNamespace
): Promise<Response> {
    const origin = request.headers.get('Origin') || '*';
    const cookies = request.headers.get('Cookie') || '';
    const sessionCookie = cookies.split(';').find(c => c.trim().startsWith('session='));
    const sessionToken = sessionCookie?.split('=')[1]?.trim();

    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': origin,
    };
    if (origin !== '*') {
        headers['Access-Control-Allow-Credentials'] = 'true';
    }

    if (!sessionToken) {
        return new Response(JSON.stringify({ user: null }), { status: 200, headers });
    }

    const sessionDataStr = await kv.get(`SESSION_${sessionToken}`);
    if (!sessionDataStr) {
        return new Response(JSON.stringify({ user: null }), { status: 200, headers });
    }

    const sessionData = JSON.parse(sessionDataStr) as SessionData;

    // Check expiration
    if (new Date(sessionData.expires_at) < new Date()) {
        await kv.delete(`SESSION_${sessionToken}`);
        return new Response(JSON.stringify({ user: null }), { status: 200, headers });
    }

    // Check System Maintenance Settings
    const settingsStr = await kv.get('SYSTEM_SETTINGS');
    const settings = settingsStr ? JSON.parse(settingsStr) : { login_linuxdo_enabled: true, login_github_enabled: true };

    // Determine provider (default to 'linuxdo' if missing)
    // Note: sessionData type in this file might need update to include auth_provider, but at runtime it handles it if present
    const provider = (sessionData as any).auth_provider || 'linuxdo';

    if (provider === 'github') {
        if (settings.login_github_enabled === false) {
            const ALLOWED_ADMINS = ['EmmaStoneX'];
            if (!ALLOWED_ADMINS.includes(sessionData.username)) {
                // Maintenance mode active, user not whitelisted -> invalid session
                return new Response(JSON.stringify({ user: null, error: 'maintenance_mode' }), { status: 200, headers });
            }
        }
    } else {
        // LinuxDO
        if (settings.login_linuxdo_enabled === false) {
            const ALLOWED_ADMINS = ['Triceratops2017'];
            if (!ALLOWED_ADMINS.includes(sessionData.username)) {
                return new Response(JSON.stringify({ user: null, error: 'maintenance_mode' }), { status: 200, headers });
            }
        }
    }

    return new Response(JSON.stringify({
        user: {
            id: sessionData.user_id,
            username: sessionData.username,
            avatar_url: sessionData.avatar_url,
            auth_provider: provider
        }
    }), { status: 200, headers });
}

/**
 * Handle logout
 */
export async function handleLogout(
    request: Request,
    kv: KVNamespace
): Promise<Response> {
    const origin = request.headers.get('Origin') || '*';
    const cookies = request.headers.get('Cookie') || '';
    const sessionCookie = cookies.split(';').find(c => c.trim().startsWith('session='));
    const sessionToken = sessionCookie?.split('=')[1]?.trim();

    if (sessionToken) {
        await kv.delete(`SESSION_${sessionToken}`);
    }

    const headers = new Headers({
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': origin,
    });
    if (origin !== '*') {
        headers.set('Access-Control-Allow-Credentials', 'true');
    }
    headers.append('Set-Cookie', 'session=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0');

    return new Response(JSON.stringify({ success: true }), { status: 200, headers });
}

/**
 * Get all users (admin only)
 */
export async function getUsers(kv: KVNamespace): Promise<Record<string, StoredUser>> {
    const usersStr = await kv.get('LINUXDO_USERS');
    return usersStr ? JSON.parse(usersStr) : {};
}

/**
 * Ban a user
 */
export async function banUser(userId: number, kv: KVNamespace): Promise<void> {
    const bannedUsersStr = await kv.get('BANNED_USERS');
    const bannedUsers: number[] = bannedUsersStr ? JSON.parse(bannedUsersStr) : [];

    if (!bannedUsers.includes(userId)) {
        bannedUsers.push(userId);
        await kv.put('BANNED_USERS', JSON.stringify(bannedUsers));
    }
}

/**
 * Unban a user
 */
export async function unbanUser(userId: number, kv: KVNamespace): Promise<void> {
    const bannedUsersStr = await kv.get('BANNED_USERS');
    const bannedUsers: number[] = bannedUsersStr ? JSON.parse(bannedUsersStr) : [];

    const index = bannedUsers.indexOf(userId);
    if (index > -1) {
        bannedUsers.splice(index, 1);
        await kv.put('BANNED_USERS', JSON.stringify(bannedUsers));
    }
}

/**
 * Get banned users list
 */
export async function getBannedUsers(kv: KVNamespace): Promise<number[]> {
    const bannedUsersStr = await kv.get('BANNED_USERS');
    return bannedUsersStr ? JSON.parse(bannedUsersStr) : [];
}
