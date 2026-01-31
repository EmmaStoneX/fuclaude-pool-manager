// src/rateLimiter.ts
// Rate Limiter and IP Ban Module for Admin Authentication

/**
 * Configuration for rate limiting
 */
export const RATE_LIMIT_CONFIG = {
    /** Maximum allowed failed attempts before banning */
    MAX_FAILED_ATTEMPTS: 3,
    /** Ban duration in seconds (15 minutes) */
    BAN_DURATION_SECONDS: 15 * 60,
    /** Time window to count failed attempts in seconds (15 minutes) */
    ATTEMPT_WINDOW_SECONDS: 15 * 60,
};

/**
 * Structure for tracking login attempts
 */
interface LoginAttemptRecord {
    /** Number of failed attempts */
    failedAttempts: number;
    /** Timestamp of first failed attempt in this window */
    firstAttemptTime: number;
    /** Timestamp when the ban will expire (if banned) */
    bannedUntil?: number;
}

/**
 * Storage key prefix for login attempts
 */
const LOGIN_ATTEMPTS_PREFIX = 'LOGIN_ATTEMPTS_';

/**
 * Get the client IP from the request
 * Cloudflare Workers provide CF-Connecting-IP header
 */
export function getClientIP(request: Request): string {
    // Cloudflare provides the real client IP in CF-Connecting-IP header
    const cfIP = request.headers.get('CF-Connecting-IP');
    if (cfIP) return cfIP;

    // Fallback to X-Forwarded-For
    const forwardedFor = request.headers.get('X-Forwarded-For');
    if (forwardedFor) {
        // Take the first IP in the chain (original client)
        return forwardedFor.split(',')[0].trim();
    }

    // Fallback to X-Real-IP
    const realIP = request.headers.get('X-Real-IP');
    if (realIP) return realIP;

    // Last resort: return a placeholder (shouldn't happen in production)
    return 'unknown';
}

/**
 * Get the login attempt record for an IP
 */
export async function getLoginAttemptRecord(
    ip: string,
    kv: KVNamespace
): Promise<LoginAttemptRecord | null> {
    const key = `${LOGIN_ATTEMPTS_PREFIX}${ip}`;
    const recordStr = await kv.get(key);
    if (!recordStr) return null;

    try {
        return JSON.parse(recordStr) as LoginAttemptRecord;
    } catch {
        return null;
    }
}

/**
 * Save the login attempt record for an IP
 */
async function saveLoginAttemptRecord(
    ip: string,
    record: LoginAttemptRecord,
    kv: KVNamespace
): Promise<void> {
    const key = `${LOGIN_ATTEMPTS_PREFIX}${ip}`;
    // Set TTL to ban duration + window to auto-cleanup old records
    const ttl = RATE_LIMIT_CONFIG.BAN_DURATION_SECONDS + RATE_LIMIT_CONFIG.ATTEMPT_WINDOW_SECONDS;
    await kv.put(key, JSON.stringify(record), { expirationTtl: ttl });
}

/**
 * Clear the login attempt record for an IP (on successful login)
 */
export async function clearLoginAttemptRecord(
    ip: string,
    kv: KVNamespace
): Promise<void> {
    const key = `${LOGIN_ATTEMPTS_PREFIX}${ip}`;
    await kv.delete(key);
}

/**
 * Check if an IP is currently banned
 * Returns the remaining ban time in seconds if banned, or 0 if not banned
 */
export async function checkIPBanned(
    ip: string,
    kv: KVNamespace
): Promise<{ banned: boolean; remainingSeconds: number; failedAttempts: number }> {
    const record = await getLoginAttemptRecord(ip, kv);

    if (!record) {
        return { banned: false, remainingSeconds: 0, failedAttempts: 0 };
    }

    const now = Date.now();

    // Check if currently banned
    if (record.bannedUntil && record.bannedUntil > now) {
        const remainingSeconds = Math.ceil((record.bannedUntil - now) / 1000);
        return {
            banned: true,
            remainingSeconds,
            failedAttempts: record.failedAttempts
        };
    }

    // Check if the attempt window has expired (reset counter)
    const windowExpiry = record.firstAttemptTime + (RATE_LIMIT_CONFIG.ATTEMPT_WINDOW_SECONDS * 1000);
    if (now > windowExpiry) {
        // Window expired, clear the record
        await clearLoginAttemptRecord(ip, kv);
        return { banned: false, remainingSeconds: 0, failedAttempts: 0 };
    }

    return {
        banned: false,
        remainingSeconds: 0,
        failedAttempts: record.failedAttempts
    };
}

/**
 * Record a failed login attempt
 * Returns true if the IP is now banned, false otherwise
 */
export async function recordFailedAttempt(
    ip: string,
    kv: KVNamespace
): Promise<{ nowBanned: boolean; attemptsRemaining: number; banDuration?: number }> {
    const now = Date.now();
    let record = await getLoginAttemptRecord(ip, kv);

    if (!record) {
        // First failed attempt
        record = {
            failedAttempts: 1,
            firstAttemptTime: now,
        };
    } else {
        // Check if window has expired
        const windowExpiry = record.firstAttemptTime + (RATE_LIMIT_CONFIG.ATTEMPT_WINDOW_SECONDS * 1000);
        if (now > windowExpiry) {
            // Reset the counter
            record = {
                failedAttempts: 1,
                firstAttemptTime: now,
            };
        } else {
            // Increment the counter
            record.failedAttempts += 1;
        }
    }

    // Check if should be banned
    if (record.failedAttempts >= RATE_LIMIT_CONFIG.MAX_FAILED_ATTEMPTS) {
        record.bannedUntil = now + (RATE_LIMIT_CONFIG.BAN_DURATION_SECONDS * 1000);
        await saveLoginAttemptRecord(ip, record, kv);

        console.warn(`[SECURITY] IP ${ip} has been banned for ${RATE_LIMIT_CONFIG.BAN_DURATION_SECONDS} seconds after ${record.failedAttempts} failed login attempts.`);

        return {
            nowBanned: true,
            attemptsRemaining: 0,
            banDuration: RATE_LIMIT_CONFIG.BAN_DURATION_SECONDS
        };
    }

    await saveLoginAttemptRecord(ip, record, kv);

    const attemptsRemaining = RATE_LIMIT_CONFIG.MAX_FAILED_ATTEMPTS - record.failedAttempts;
    console.warn(`[SECURITY] Failed login attempt from IP ${ip}. Attempts remaining: ${attemptsRemaining}`);

    return {
        nowBanned: false,
        attemptsRemaining
    };
}

/**
 * Record a successful login (clears the failed attempt counter)
 */
export async function recordSuccessfulLogin(
    ip: string,
    kv: KVNamespace
): Promise<void> {
    await clearLoginAttemptRecord(ip, kv);
    console.log(`[SECURITY] Successful admin login from IP ${ip}. Failed attempt counter cleared.`);
}

/**
 * Get all currently banned IPs (for admin monitoring)
 */
export async function getBannedIPs(kv: KVNamespace): Promise<Array<{ ip: string; bannedUntil: number; failedAttempts: number }>> {
    // Note: This requires listing keys which may not be efficient for large datasets
    // In production, you might want to maintain a separate list of banned IPs
    const bannedList: Array<{ ip: string; bannedUntil: number; failedAttempts: number }> = [];
    const now = Date.now();

    // Use list to get all keys with the prefix
    const keys = await kv.list({ prefix: LOGIN_ATTEMPTS_PREFIX });

    for (const key of keys.keys) {
        const recordStr = await kv.get(key.name);
        if (recordStr) {
            try {
                const record = JSON.parse(recordStr) as LoginAttemptRecord;
                if (record.bannedUntil && record.bannedUntil > now) {
                    const ip = key.name.replace(LOGIN_ATTEMPTS_PREFIX, '');
                    bannedList.push({
                        ip,
                        bannedUntil: record.bannedUntil,
                        failedAttempts: record.failedAttempts,
                    });
                }
            } catch {
                // Ignore parse errors
            }
        }
    }

    return bannedList;
}
