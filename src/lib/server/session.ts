import type { OIDCSession, OIDCSessionTokens, OIDCTokenResponse } from './types.js';

export function normalizeTokens(
	tokenResponse: OIDCTokenResponse,
	defaultScope: string[],
	existing?: OIDCSessionTokens,
	now = Math.floor(Date.now() / 1000)
): OIDCSessionTokens {
	return {
		accessToken: tokenResponse.access_token,
		tokenType: tokenResponse.token_type,
		idToken: tokenResponse.id_token ?? existing?.idToken,
		refreshToken: tokenResponse.refresh_token ?? existing?.refreshToken,
		scope: tokenResponse.scope ? tokenResponse.scope.split(' ') : (existing?.scope ?? defaultScope),
		expiresAt: tokenResponse.expires_in ? now + tokenResponse.expires_in : existing?.expiresAt,
		refreshExpiresAt: tokenResponse.refresh_expires_in
			? now + tokenResponse.refresh_expires_in
			: existing?.refreshExpiresAt
	};
}

export function shouldRefresh(
	session: OIDCSession,
	refreshToleranceSeconds: number,
	now = Math.floor(Date.now() / 1000)
) {
	if (!session.tokens.expiresAt || !session.tokens.refreshToken) {
		return false;
	}

	return session.tokens.expiresAt - refreshToleranceSeconds <= now;
}
