import type {CookieOptions, OIDCCookies, OIDCSession, OIDCUserClaims} from './types.js';
import {parseSignedCookie, serializeSignedCookie} from './utils.js';

export function createOIDCCookieStore<TIdentity extends OIDCUserClaims = OIDCUserClaims>(
	cookieSecret: string,
	sessionCookieName: string,
	stateCookieName: string,
	cookieOptions: CookieOptions
): OIDCCookies<TIdentity> {
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
		readSessionReference(cookies) {
			return parseSignedCookie(cookies.get(sessionCookieName), cookieSecret);
		},
		writeSessionReference(cookies, reference) {
			cookies.set(sessionCookieName, serializeSignedCookie(reference, cookieSecret), cookieOptions);
		},
		clearSessionReference(cookies) {
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
