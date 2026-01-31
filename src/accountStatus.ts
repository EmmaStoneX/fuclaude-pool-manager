// src/accountStatus.ts
// Account Status and Usage Tracking Module

/**
 * Account metadata stored in KV
 */
export interface AccountMetadata {
    /** Email address */
    email: string;
    /** Whether this account was contributed by a user */
    isContributed: boolean;
    /** Timestamp when the account was added */
    addedAt: number;
    /** Number of currently active sessions */
    activeSessions: number;
    /** Last time someone logged in with this account */
    lastUsedAt?: number;
    /** Is the account valid (last health check result) */
    isValid: boolean;
    /** Last health check timestamp */
    lastHealthCheck?: number;
}

/**
 * Account status types for UI display
 */
export type AccountStatusType = 'available' | 'busy' | 'unavailable';

/**
 * Thresholds for status determination
 */
export const STATUS_THRESHOLDS = {
    /** Max sessions before considered "busy" (starts at yellow) */
    BUSY_THRESHOLD: 10,
    /** Max sessions before considered "overloaded" (still yellow/busy, but high usage) */
    OVERLOAD_THRESHOLD: 20,
};

/**
 * Storage key for account metadata
 */
const ACCOUNT_METADATA_KEY = 'ACCOUNT_METADATA_MAP';
const ACTIVE_SESSIONS_KEY = 'ACTIVE_SESSIONS_MAP';

/**
 * Get all account metadata from KV
 */
export async function getAccountMetadataMap(kv: KVNamespace): Promise<Record<string, AccountMetadata>> {
    const mapStr = await kv.get(ACCOUNT_METADATA_KEY);
    if (!mapStr) return {};
    try {
        return JSON.parse(mapStr) as Record<string, AccountMetadata>;
    } catch {
        return {};
    }
}

/**
 * Save account metadata map to KV
 */
export async function saveAccountMetadataMap(kv: KVNamespace, map: Record<string, AccountMetadata>): Promise<void> {
    await kv.put(ACCOUNT_METADATA_KEY, JSON.stringify(map));
}

/**
 * Get active sessions map from KV
 */
export async function getActiveSessionsMap(kv: KVNamespace): Promise<Record<string, number>> {
    const mapStr = await kv.get(ACTIVE_SESSIONS_KEY);
    if (!mapStr) return {};
    try {
        return JSON.parse(mapStr) as Record<string, number>;
    } catch {
        return {};
    }
}

/**
 * Save active sessions map to KV
 */
export async function saveActiveSessionsMap(kv: KVNamespace, map: Record<string, number>): Promise<void> {
    await kv.put(ACTIVE_SESSIONS_KEY, JSON.stringify(map));
}

/**
 * Record a login event for an account
 */
export async function recordLogin(email: string, kv: KVNamespace): Promise<void> {
    const sessionsMap = await getActiveSessionsMap(kv);
    sessionsMap[email] = (sessionsMap[email] || 0) + 1;
    await saveActiveSessionsMap(kv, sessionsMap);

    // Also update last used time in metadata
    const metadataMap = await getAccountMetadataMap(kv);
    if (metadataMap[email]) {
        metadataMap[email].lastUsedAt = Date.now();
        metadataMap[email].activeSessions = sessionsMap[email];
        await saveAccountMetadataMap(kv, metadataMap);
    }
}

/**
 * Determine the status of an account based on active sessions
 */
export function getAccountStatus(activeSessions: number, isValid: boolean): AccountStatusType {
    if (!isValid) {
        return 'unavailable'; // Red: Failed health check
    }
    // Even if overloaded, as long as it's valid, we show it as busy (Yellow) or maybe a different shade, 
    // but user specified: 1-10 Green, >10 Busy. Red is for invalid.
    if (activeSessions >= STATUS_THRESHOLDS.BUSY_THRESHOLD) {
        return 'busy';
    }
    return 'available';
}

/**
 * Initialize or update metadata for an account
 */
export async function initAccountMetadata(
    email: string,
    kv: KVNamespace,
    isContributed: boolean = false,
    isValid: boolean = true
): Promise<AccountMetadata> {
    const metadataMap = await getAccountMetadataMap(kv);
    const sessionsMap = await getActiveSessionsMap(kv);

    const existing = metadataMap[email];
    const now = Date.now();

    const metadata: AccountMetadata = {
        email,
        isContributed: existing?.isContributed || isContributed,
        addedAt: existing?.addedAt || now,
        activeSessions: sessionsMap[email] || 0,
        lastUsedAt: existing?.lastUsedAt,
        isValid,
        lastHealthCheck: now,
    };

    metadataMap[email] = metadata;
    await saveAccountMetadataMap(kv, metadataMap);

    return metadata;
}

/**
 * Mark an account as contributed
 */
export async function markAsContributed(email: string, kv: KVNamespace): Promise<void> {
    const metadataMap = await getAccountMetadataMap(kv);
    if (metadataMap[email]) {
        metadataMap[email].isContributed = true;
        await saveAccountMetadataMap(kv, metadataMap);
    } else {
        await initAccountMetadata(email, kv, true, true);
    }
}

/**
 * Remove account metadata
 */
export async function removeAccountMetadata(email: string, kv: KVNamespace): Promise<void> {
    const metadataMap = await getAccountMetadataMap(kv);
    delete metadataMap[email];
    await saveAccountMetadataMap(kv, metadataMap);

    const sessionsMap = await getActiveSessionsMap(kv);
    delete sessionsMap[email];
    await saveActiveSessionsMap(kv, sessionsMap);
}

/**
 * Verify if an SK is valid by attempting a token exchange
 */
export async function verifyAccountHealth(
    email: string,
    sk: string,
    baseUrl: string
): Promise<{ isValid: boolean; message?: string }> {
    try {
        const uniqueName = `health_check_${Date.now()}_${Math.random().toString(36).substring(7)}`;
        const oauthPayload = { session_key: sk, unique_name: uniqueName, expires_in: 60 };

        const response = await fetch(`${baseUrl}/manage-api/auth/oauth_token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(oauthPayload),
        });

        if (response.ok) {
            const data: any = await response.json();
            if (data && data.login_url) {
                return { isValid: true };
            }
            return { isValid: false, message: 'No login_url in response' };
        }

        return { isValid: false, message: `HTTP ${response.status}` };
    } catch (error: any) {
        return { isValid: false, message: error.message || 'Network error' };
    }
}

/**
 * Get enriched account list with status information
 */
/**
 * Helper to get account status map (health check results)
 */
async function getHealthCheckStatusMap(kv: KVNamespace): Promise<Record<string, { isValid: boolean, message?: string }>> {
    const mapStr = await kv.get('ACCOUNT_STATUS_MAP');
    if (!mapStr) return {};
    try {
        return JSON.parse(mapStr) as Record<string, { isValid: boolean, message?: string }>;
    } catch {
        return {};
    }
}

export async function getEnrichedAccountList(
    emails: string[],
    kv: KVNamespace
): Promise<Array<{
    email: string;
    status: AccountStatusType;
    isContributed: boolean;
    activeSessions: number;
}>> {
    const metadataMap = await getAccountMetadataMap(kv);
    const sessionsMap = await getActiveSessionsMap(kv);
    const healthStatusMap = await getHealthCheckStatusMap(kv);

    return emails.map(email => {
        const metadata = metadataMap[email];
        const activeSessions = sessionsMap[email] || 0;

        // Priority for validity:
        // 1. Health Check Map (most recent admin check)
        // 2. Metadata (stored state)
        // 3. Default true
        let isValid = true;

        if (healthStatusMap[email]) {
            isValid = healthStatusMap[email].isValid;
        } else if (metadata) {
            isValid = metadata.isValid;
        }

        return {
            email,
            status: getAccountStatus(activeSessions, isValid),
            isContributed: metadata?.isContributed || false,
            activeSessions,
        };
    });
}

/**
 * Decay active sessions over time (call periodically)
 * Reduces active session count to simulate session expiry
 */
export async function decayActiveSessions(kv: KVNamespace): Promise<void> {
    const sessionsMap = await getActiveSessionsMap(kv);
    const metadataMap = await getAccountMetadataMap(kv);

    for (const email of Object.keys(sessionsMap)) {
        // Reduce by 1, but don't go below 0
        if (sessionsMap[email] > 0) {
            sessionsMap[email] = Math.max(0, sessionsMap[email] - 1);
        }
        // Update metadata as well
        if (metadataMap[email]) {
            metadataMap[email].activeSessions = sessionsMap[email];
        }
    }

    await saveActiveSessionsMap(kv, sessionsMap);
    await saveAccountMetadataMap(kv, metadataMap);
}
