import type {
	OIDCBackChannelLogoutStore,
	OIDCSession,
	OIDCSessionStore,
	OIDCUserClaims
} from './types.js';

export function createInMemoryBackChannelLogoutStore<
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
>(): OIDCBackChannelLogoutStore<TClaims, TSession> {
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
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
>(): OIDCSessionStore<TClaims, TSession> {
	const sessions = new Map<string, Parameters<OIDCSessionStore<TClaims, TSession>['set']>[1]>();

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
