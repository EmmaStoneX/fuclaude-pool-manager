import * as auth from './auth';
import * as githubAuth from './githubAuth';

/**
 * Unified user info for admin management
 */
interface UnifiedUserInfo {
    id: number;
    username: string;
    name?: string;
    avatar_url?: string;
    trust_level?: number;
    email?: string;
    first_login: string;
    last_login: string;
    login_count: number;
    is_banned: boolean;
    auth_provider: 'linuxdo' | 'github';
}

/**
 * Handle user management API endpoints
 */
export async function handleUserManagement(
    request: Request,
    url: URL,
    kv: KVNamespace
): Promise<Response | null> {
    const corsHeaders = {
        'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
        'Access-Control-Allow-Credentials': 'true',
        'Content-Type': 'application/json',
    };

    // POST /api/admin/users: Get all users (LinuxDO + GitHub)
    if (url.pathname === '/api/admin/users' && request.method === 'POST') {
        // Get LinuxDO users
        const linuxdoUsers = await auth.getUsers(kv);
        const bannedLinuxdoUsers = await auth.getBannedUsers(kv);

        // Get GitHub users
        const githubUsers = await githubAuth.getGitHubUsers(kv);
        const bannedGitHubUsers = await githubAuth.getBannedGitHubUsers(kv);

        // Transform LinuxDO users
        const linuxdoUserList: UnifiedUserInfo[] = Object.values(linuxdoUsers).map(user => ({
            id: user.id,
            username: user.username,
            name: user.name,
            avatar_url: user.avatar_url,
            trust_level: user.trust_level,
            email: user.email,
            first_login: user.first_login,
            last_login: user.last_login,
            login_count: user.login_count,
            is_banned: bannedLinuxdoUsers.includes(user.id),
            auth_provider: 'linuxdo' as const
        }));

        // Transform GitHub users
        const githubUserList: UnifiedUserInfo[] = Object.values(githubUsers).map(user => ({
            id: user.id,
            username: user.username,
            name: user.name,
            avatar_url: user.avatar_url,
            email: user.email,
            first_login: user.first_login,
            last_login: user.last_login,
            login_count: user.login_count,
            is_banned: bannedGitHubUsers.includes(user.id),
            auth_provider: 'github' as const
        }));

        // Combine and sort by last_login descending
        const allUsers = [...linuxdoUserList, ...githubUserList];
        allUsers.sort((a, b) => new Date(b.last_login).getTime() - new Date(a.last_login).getTime());

        const totalBanned = bannedLinuxdoUsers.length + bannedGitHubUsers.length;

        return new Response(JSON.stringify({
            users: allUsers,
            banned_count: totalBanned,
            linuxdo_count: linuxdoUserList.length,
            github_count: githubUserList.length
        }), {
            status: 200,
            headers: corsHeaders,
        });
    }

    // POST /api/admin/users/ban: Ban a user
    if (url.pathname === '/api/admin/users/ban' && request.method === 'POST') {
        const body = await request.json() as { admin_password: string; user_id: number; auth_provider?: 'linuxdo' | 'github' };
        if (typeof body.user_id !== 'number') {
            return new Response(JSON.stringify({ error: 'user_id is required and must be a number.' }), {
                status: 400,
                headers: corsHeaders,
            });
        }

        const provider = body.auth_provider || 'linuxdo';

        if (provider === 'github') {
            await githubAuth.banGitHubUser(body.user_id, kv);
            console.log(`Admin action: GitHub user ${body.user_id} banned.`);
        } else {
            await auth.banUser(body.user_id, kv);
            console.log(`Admin action: LinuxDO user ${body.user_id} banned.`);
        }

        return new Response(JSON.stringify({ message: `User ${body.user_id} (${provider}) has been banned.` }), {
            status: 200,
            headers: corsHeaders,
        });
    }

    // POST /api/admin/users/unban: Unban a user
    if (url.pathname === '/api/admin/users/unban' && request.method === 'POST') {
        const body = await request.json() as { admin_password: string; user_id: number; auth_provider?: 'linuxdo' | 'github' };
        if (typeof body.user_id !== 'number') {
            return new Response(JSON.stringify({ error: 'user_id is required and must be a number.' }), {
                status: 400,
                headers: corsHeaders,
            });
        }

        const provider = body.auth_provider || 'linuxdo';

        if (provider === 'github') {
            await githubAuth.unbanGitHubUser(body.user_id, kv);
            console.log(`Admin action: GitHub user ${body.user_id} unbanned.`);
        } else {
            await auth.unbanUser(body.user_id, kv);
            console.log(`Admin action: LinuxDO user ${body.user_id} unbanned.`);
        }

        return new Response(JSON.stringify({ message: `User ${body.user_id} (${provider}) has been unbanned.` }), {
            status: 200,
            headers: corsHeaders,
        });
    }

    // Not a user management endpoint
    return null;
}

