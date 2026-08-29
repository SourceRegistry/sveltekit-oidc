import type {CookieOptions, OIDCCookies, OIDCSession, OIDCUserClaims} from './types.js';
import {parseSignedCookie, serializeSignedCookie} from './utils.js';

export function createOIDCCookieStore<TIdentity extends OIDCUserClaims = OIDCUserClaims>(
    cookieSecret: string,
    sessionCookieName: string,
    stateCookieName: string,
    cookieOptions: CookieOptions,
    stateMaxAgeSeconds: number,
    maxCookieSizeBytes: number
): OIDCCookies<TIdentity> {
    const stateCookiePrefix = `${stateCookieName}.`;
    const stateName = (token: string) => `${stateCookiePrefix}${token.slice(0, 16)}`;
    const assertCookieSize = (name: string, value: string) => {
        if (Buffer.byteLength(`${name}=${value}`, 'utf8') > maxCookieSizeBytes) {
            throw new TypeError(
                `OIDC cookie '${name}' exceeds ${maxCookieSizeBytes} bytes; configure sessionStore to keep tokens server-side`
            );
        }
    };

    return {
        readSession(cookies) {
            return parseSignedCookie(cookies.get(sessionCookieName), cookieSecret);
        },
        writeSession(cookies, session) {
            const value = serializeSignedCookie(session, cookieSecret);
            assertCookieSize(sessionCookieName, value);
            cookies.set(sessionCookieName, value, cookieOptions);
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
        readState(cookies, stateToken) {
            const transactionValue = stateToken ? cookies.get(stateName(stateToken)) : undefined;
            return parseSignedCookie(transactionValue ?? cookies.get(stateCookieName), cookieSecret);
        },
        writeState(cookies, state) {
            const name = stateName(state.state);
            const value = serializeSignedCookie(state, cookieSecret);
            assertCookieSize(name, value);
            cookies.set(name, value, {
                ...cookieOptions,
                maxAge: stateMaxAgeSeconds
            });
        },
        clearState(cookies, stateToken) {
            if (stateToken) cookies.delete(stateName(stateToken), cookieOptions);
            cookies.delete(stateCookieName, cookieOptions);
            if (!stateToken) {
                for (const cookie of cookies.getAll()) {
                    if (cookie.name.startsWith(stateCookiePrefix)) cookies.delete(cookie.name, cookieOptions);
                }
            }
        }
    };
}
