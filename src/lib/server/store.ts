import type {OIDCBackChannelLogoutStore, OIDCSession, OIDCSessionStore, OIDCUserClaims} from './types.js';

export function createInMemoryBackChannelLogoutStore<TIdentity extends OIDCUserClaims = OIDCUserClaims>(
    options: {retentionSeconds?: number} = {}
): OIDCBackChannelLogoutStore<TIdentity> {
    type Revocation = {issuedAt: number; removeAt: number};
    const retentionSeconds = options.retentionSeconds ?? 60 * 60 * 8;
    const revokedBySid = new Map<string, Revocation>();
    const revokedBySub = new Map<string, Revocation>();

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
            if (record.sid) {
                remember(revokedBySid, `${record.issuer}:${record.clientId}:${record.sid}`, record.iat);
            }
            if (record.sub) {
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

export function createInMemorySessionStore<
    TIdentity extends OIDCUserClaims = OIDCUserClaims
>(): OIDCSessionStore<TIdentity> {
    type Sessions = Map<string, Parameters<OIDCSessionStore<TIdentity>['set']>[1]>;
    // Persist the Map on globalThis so Vite HMR module re-evaluations don't
    // create a fresh store and orphan all live session cookies.
    const g = globalThis as Record<string, unknown>;
    const sessions = (g['__oidc_sessions__'] ??= new Map()) as Sessions;

    return {
        async get(sessionId) {
            return sessions.get(sessionId) ?? null;
        },
        async set(sessionId, session) {
            sessions.set(sessionId, session);
        },
        async delete(sessionId) {
            sessions.delete(sessionId);
        }
    };
}
