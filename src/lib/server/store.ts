import '$app/server';
import type {OIDCBackChannelLogoutStore, OIDCSession, OIDCSessionStore, OIDCUserClaims} from './types.js';

/** How often expired entries are swept from the in-memory stores. */
const SWEEP_INTERVAL_MS = 60_000;

export function createInMemoryBackChannelLogoutStore<TIdentity extends OIDCUserClaims = OIDCUserClaims>(
    options: {retentionSeconds?: number} = {}
): OIDCBackChannelLogoutStore<TIdentity> {
    type Revocation = {issuedAt: number; removeAt: number};
    const retentionSeconds = options.retentionSeconds ?? 60 * 60 * 8;
    const revokedBySid = new Map<string, Revocation>();
    const revokedBySub = new Map<string, Revocation>();
    let lastSweepAt = Date.now();

    function sweep() {
        const nowMs = Date.now();
        if (nowMs - lastSweepAt < SWEEP_INTERVAL_MS) return;
        lastSweepAt = nowMs;
        const now = Math.floor(nowMs / 1000);
        for (const map of [revokedBySid, revokedBySub]) {
            for (const [key, record] of map) {
                if (record.removeAt <= now) map.delete(key);
            }
        }
    }

    function remember(map: Map<string, Revocation>, key: string, issuedAt: number) {
        map.set(key, {
            issuedAt,
            removeAt: Math.floor(Date.now() / 1000) + retentionSeconds
        });
    }

    function matches(map: Map<string, Revocation>, key: string | undefined, sessionCreatedAt: number) {
        if (!key) return false;
        const record = map.get(key);
        if (!record) return false;
        if (record.removeAt <= Math.floor(Date.now() / 1000)) {
            map.delete(key);
            return false;
        }
        // A later login is a new session and must not inherit a subject-wide revocation.
        return sessionCreatedAt <= record.issuedAt;
    }

    return {
        async revoke(record) {
            sweep();
            if (record.sid) {
                remember(revokedBySid, `${record.issuer}:${record.clientId}:${record.sid}`, record.iat);
            }
            // A subject-only logout applies to every session for the End-User.
            // When sid is present, the provider identified one session.
            if (record.sub && !record.sid) {
                remember(revokedBySub, `${record.issuer}:${record.clientId}:${record.sub}`, record.iat);
            }
        },
        async isRevoked(session) {
            return Boolean(
                matches(
                    revokedBySid,
                    session.sid ? `${session.issuer}:${session.clientId}:${session.sid}` : undefined,
                    session.createdAt
                ) ||
                matches(
                    revokedBySub,
                    session.sub ? `${session.issuer}:${session.clientId}:${session.sub}` : undefined,
                    session.createdAt
                )
            );
        }
    };
}

export type InMemorySessionStoreOptions = {
    /**
     * Sessions older than this (by `createdAt`) are dropped. Match it to the
     * `sessionMaxAgeSeconds` option; `createOIDC` does so for `sessionStore: 'memory'`.
     * Defaults to 8 hours.
     */
    maxAgeSeconds?: number;
    /** Upper bound on stored sessions; the least recently written are evicted first. Defaults to 10000. */
    maxEntries?: number;
};

export function createInMemorySessionStore<TIdentity extends OIDCUserClaims = OIDCUserClaims>(
    options: InMemorySessionStoreOptions = {}
): OIDCSessionStore<TIdentity> {
    type Entry = {session: OIDCSession<TIdentity>; expiresAt: number};
    const maxAgeSeconds = options.maxAgeSeconds ?? 60 * 60 * 8;
    const maxEntries = options.maxEntries ?? 10_000;
    if (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds <= 0) {
        throw new TypeError('maxAgeSeconds must be a positive finite number');
    }
    if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
        throw new TypeError('maxEntries must be a positive integer');
    }
    // Persist the Map on globalThis so Vite HMR module re-evaluations don't
    // create a fresh store and orphan all live session cookies.
    const g = globalThis as Record<string, unknown>;
    const sessions = (g['__oidc_session_entries__'] ??= new Map()) as Map<string, Entry>;
    let lastSweepAt = Date.now();

    const now = () => Math.floor(Date.now() / 1000);

    function sweep() {
        if (Date.now() - lastSweepAt < SWEEP_INTERVAL_MS) return;
        lastSweepAt = Date.now();
        const current = now();
        for (const [id, entry] of sessions) {
            if (entry.expiresAt <= current) sessions.delete(id);
        }
    }

    return {
        async get(sessionId) {
            const entry = sessions.get(sessionId);
            if (!entry) return null;
            if (entry.expiresAt <= now()) {
                sessions.delete(sessionId);
                return null;
            }
            return entry.session;
        },
        async set(sessionId, session) {
            sweep();
            // Re-insert so Map order tracks the most recent write.
            sessions.delete(sessionId);
            sessions.set(sessionId, {session, expiresAt: session.createdAt + maxAgeSeconds});
            while (sessions.size > maxEntries) {
                const oldest = sessions.keys().next().value;
                if (oldest === undefined) break;
                sessions.delete(oldest);
            }
        },
        async delete(sessionId) {
            sessions.delete(sessionId);
        }
    };
}
