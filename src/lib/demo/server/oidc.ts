import { env } from '$env/dynamic/private';
import { createInMemoryBackChannelLogoutStore, createOIDC } from '$lib/server/index.js';

const issuer = env.OIDC_ISSUER?.trim();
const clientId = env.OIDC_CLIENT_ID?.trim();
const cookieSecret = env.OIDC_COOKIE_SECRET?.trim();

const scope = env.OIDC_SCOPE?.trim()
	? env.OIDC_SCOPE.split(/[,\s]+/).filter(Boolean)
	: ['openid', 'profile', 'email'];

export const demoOIDC =
	issuer && clientId && cookieSecret
		? createOIDC({
				issuer,
				clientId,
				clientSecret: env.OIDC_CLIENT_SECRET?.trim() || undefined,
				cookieSecret,
				postLogoutRedirectUri: env.OIDC_POST_LOGOUT_REDIRECT_URI?.trim() || undefined,
				scope,
				fetchUserInfo: true,
				backChannelLogoutStore: createInMemoryBackChannelLogoutStore(),
				cookieOptions: {
					secure: env.NODE_ENV === 'production'
				},
				transformSession(session) {
					return {
						...session,
						groups: session.groups,
						user: session.user
							? {
									...session.user,
									groups: session.groups
								}
							: session.user
					};
				}
			})
		: null;
