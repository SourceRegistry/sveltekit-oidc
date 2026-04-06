import type { CookieOptions, OIDCCookies } from './types.js';
import { parseSignedCookie, serializeSignedCookie } from './utils.js';

export function createOIDCCookieStore(
	cookieSecret: string,
	sessionCookieName: string,
	stateCookieName: string,
	cookieOptions: CookieOptions
): OIDCCookies {
	return {
		readSession(cookies) {
			return parseSignedCookie(cookies.get(sessionCookieName), cookieSecret);
		},
		writeSession(cookies, session) {
			cookies.set(sessionCookieName, serializeSignedCookie(session, cookieSecret), cookieOptions);
		},
		clearSession(cookies) {
			cookies.delete(sessionCookieName, cookieOptions);
		},
		readState(cookies) {
			return parseSignedCookie(cookies.get(stateCookieName), cookieSecret);
		},
		writeState(cookies, state) {
			cookies.set(stateCookieName, serializeSignedCookie(state, cookieSecret), {
				...cookieOptions,
				maxAge: 60 * 10
			});
		},
		clearState(cookies) {
			cookies.delete(stateCookieName, cookieOptions);
		}
	};
}
