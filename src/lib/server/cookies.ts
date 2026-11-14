import type {CookieOptions, OIDCCookies, OIDCSession, OIDCUserClaims} from './types.js';
import {type CookieSecrets, isOAuthStateToken, parseSignedCookie, serializeSignedCookie} from './utils.js';

export function createOIDCCookieStore<TIdentity extends OIDCUserClaims = OIDCUserClaims>(
    cookieSecret: CookieSecrets,
    sessionCookieName: string,
    stateCookieName: string,
    cookieOptions: CookieOptions,
    stateMaxAgeSeconds: number,
    maxCookieSizeBytes: number
): OIDCCookies<TIdentity> {
    // The provider redirects back to the callback cross-site, so a Strict state
    // cookie would never be sent and every callback would restart the login.
    const stateSameSite =
        cookieOptions.sameSite === 'strict' || cookieOptions.sameSite === true ? 'lax' : cookieOptions.sameSite;
    const stateCookiePrefix = `${stateCookieName}.`;
    // Only well-formed random tokens may become part of a cookie name; a value
    // taken from the request with other characters would make Set-Cookie throw.
    const stateName = (token: string | null | undefined) =>
        isOAuthStateToken(token) ? `${stateCookiePrefix}${token.slice(0, 16)}` : undefined;
    const assertCookieSize = (name: string, value: string) => {
        if (Buffer.byteLength(`${name}=${value}`, 'utf8') > maxCookieSizeBytes) {
            throw new TypeError(
                `OIDC cookie '${name}' exceeds ${maxCookieSizeBytes} bytes; configure sessionStore to keep tokens server-side`
            );
        }
    };

    return {
        readSession(cookies) {
            return parseSignedCookie<OIDCSession<TIdentity>>(cookies.get(sessionCookieName), cookieSecret, 'session');
        },
        writeSession(cookies, session) {
            const value = serializeSignedCookie(session, cookieSecret, 'session');
            assertCookieSize(sessionCookieName, value);
            cookies.set(sessionCookieName, value, cookieOptions);
        },
        clearSession(cookies) {
            cookies.delete(sessionCookieName, cookieOptions);
        },
        readSessionReference(cookies) {
            return parseSignedCookie(cookies.get(sessionCookieName), cookieSecret, 'session-reference');
        },
        writeSessionReference(cookies, reference) {
            cookies.set(
                sessionCookieName,
                serializeSignedCookie(reference, cookieSecret, 'session-reference'),
                cookieOptions
            );
        },
        clearSessionReference(cookies) {
            cookies.delete(sessionCookieName, cookieOptions);
        },
        readState(cookies, stateToken) {
            const name = stateName(stateToken);
            const transactionValue = name ? cookies.get(name) : undefined;
            return parseSignedCookie(transactionValue ?? cookies.get(stateCookieName), cookieSecret, 'state');
        },
        writeState(cookies, state) {
            const name = stateName(state.state);
            if (!name) throw new TypeError('OIDC state token must be a base64url string');
            const value = serializeSignedCookie(state, cookieSecret, 'state');
            assertCookieSize(name, value);
            cookies.set(name, value, {
                ...cookieOptions,
                sameSite: stateSameSite,
                maxAge: stateMaxAgeSeconds
            });
        },
        clearState(cookies, stateToken) {
            const name = stateName(stateToken);
            if (name) cookies.delete(name, cookieOptions);
            cookies.delete(stateCookieName, cookieOptions);
            if (!stateToken) {
                for (const cookie of cookies.getAll()) {
                    if (cookie.name.startsWith(stateCookiePrefix)) cookies.delete(cookie.name, cookieOptions);
                }
            }
        }
    };
}
