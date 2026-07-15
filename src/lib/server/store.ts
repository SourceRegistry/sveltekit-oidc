import type {OIDCBackChannelLogoutStore, OIDCSession, OIDCSessionStore, OIDCUserClaims} from './types.js';

export function createInMemoryBackChannelLogoutStore<
	TIdentity extends OIDCUserClaims = OIDCUserClaims
>(): OIDCBackChannelLogoutStore<TIdentity> {
	const revokedBySid = new Set<string>();
	const revokedBySub = new Set<string>();

	return {
		async revoke(record) {
			if (record.sid) {
				revokedBySid.add(`${record.issuer}:${record.clientId}:${record.sid}`);
			}
			if (record.sub) {
				revokedBySub.add(`${record.issuer}:${record.clientId}:${record.sub}`);
			}
		},
		async isRevoked(session) {
			return Boolean(
				(session.sid && revokedBySid.has(`${session.issuer}:${session.clientId}:${session.sid}`)) ||
				(session.sub && revokedBySub.has(`${session.issuer}:${session.clientId}:${session.sub}`))
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
