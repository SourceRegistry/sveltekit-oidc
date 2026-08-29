import {error} from '@sveltejs/kit';
import {createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual} from 'node:crypto';

import type {CookieOptions, OIDCPublicSession, OIDCSession, OIDCUserClaims} from './types.js';

export function base64UrlEncode(value: string | Uint8Array): string {
    const buffer = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
    return buffer.toString('base64url');
}

export function createPKCEPair(length = 64) {
    const verifier = base64UrlEncode(randomBytes(length)).slice(0, length);
    const challenge = createHash('sha256').update(verifier).digest('base64url');

    return {verifier, challenge};
}

export function normalizeIssuer(issuer: string) {
    return issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
}

export function normalizeScope(scope?: string | string[]) {
    if (!scope) return ['openid', 'profile', 'email'];
    const arr = (typeof scope === 'string' ? scope.trim().split(/\s+/) : scope).filter(Boolean);
    if (!arr.length) return ['openid', 'profile', 'email'];
    const unique = [...new Set(arr)];
    return unique.includes('openid') ? unique : ['openid', ...unique];
}

export function normalizeStringArray(value: unknown): string[] {
    if (!value) return [];
    if (Array.isArray(value)) {
        return value.filter((item): item is string => typeof item === 'string');
    }
    if (typeof value === 'string') {
        return value.trim() ? [value] : [];
    }

    return [];
}

export function collectGroups<TClaims extends OIDCUserClaims = OIDCUserClaims>(...sources: Array<TClaims | undefined>) {
    return [
        ...new Set(
            sources.flatMap((source) =>
                normalizeStringArray(source?.groups).concat(normalizeStringArray(source?.roles))
            )
        )
    ];
}

export function createSignedValue(value: string, secret: string) {
    const mac = createHmac('sha256', secret).update(value).digest('base64url');
    return `${value}.${mac}`;
}

export function verifySignedValue(value: string, secret: string) {
    const lastDot = value.lastIndexOf('.');
    if (lastDot === -1) return null;

    const payload = value.slice(0, lastDot);
    const signature = value.slice(lastDot + 1);
    const expected = createHmac('sha256', secret).update(payload).digest();
    const actual = Buffer.from(signature, 'base64url');

    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
        return null;
    }

    return payload;
}

/**
 * Embeds an app-supplied `returnTo` destination directly in the OAuth
 * `state` parameter sent to the authorization endpoint, encrypted and
 * authenticated with the same cookie secret used everywhere else here.
 *
 * The encrypted payload keeps the destination confidential while allowing
 * it to survive the authorization-server round trip. The random token is
 * still compared with the matching transaction cookie by the callback.
 */
export function encodeOAuthState(token: string, returnTo: string | undefined, secret: string): string {
    if (!returnTo) return token;
    return `v3.${serializeSignedCookie({token, returnTo}, secret)}`;
}

/**
 * Inverse of encodeOAuthState. Always returns whatever `token` it can parse
 * out - including from a bare, pre-upgrade-format state with no embedded
 * `returnTo`, so an in-flight login started before a version bump that adds
 * this encoding keeps working - and a `returnTo` only when an encrypted
 * payload authenticates successfully. Forged or corrupted current-format
 * state values are rejected. The legacy signed suffix remains readable so
 * an authorization request begun before an upgrade can finish.
 *
 * This does NOT authenticate the caller by itself - `token` still has to be
 * compared against the value in the state cookie by callers, exactly as
 * before. The `returnTo` recovered here is only ever used to decide where
 * to send the browser next (see handleCallback's restart-on-mismatch path
 * in index.ts); nothing security-sensitive is decided from it, so a
 * same-origin-only destination recovered without the cookie is fine.
 */
export function decodeOAuthState(
    raw: string | null | undefined,
    secret: string
): {token: string | null; returnTo?: string} {
    if (!raw) return {token: null};
    if (raw.startsWith('v3.')) {
        const decoded = parseSignedCookie<{token?: unknown; returnTo?: unknown}>(raw.slice(3), secret);
        if (!decoded || typeof decoded.token !== 'string') return {token: null};
        return {
            token: decoded.token,
            ...(typeof decoded.returnTo === 'string' ? {returnTo: decoded.returnTo} : {})
        };
    }

    const separator = raw.indexOf('.');
    if (separator === -1) return {token: raw};

    const token = raw.slice(0, separator);
    const signedReturnTo = raw.slice(separator + 1);
    const encodedReturnTo = verifySignedValue(signedReturnTo, secret);
    if (!encodedReturnTo) return {token};

    try {
        return {
            token,
            returnTo: Buffer.from(encodedReturnTo, 'base64url').toString('utf8')
        };
    } catch {
        return {token};
    }
}

function cookieEncryptionKey(secret: string) {
    return createHash('sha256').update(`sveltekit-oidc-cookie:${secret}`).digest();
}

export function serializeSignedCookie(payload: unknown, secret: string) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', cookieEncryptionKey(secret), iv);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return `v2.${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`;
}

export function parseSignedCookie<T>(value: string | undefined, secret: string): T | null {
    if (!value) return null;

    const parts = value.split('.');
    if (parts.length !== 4 || parts[0] !== 'v2') return null;

    try {
        const [, iv, tag, ciphertext] = parts;
        const decipher = createDecipheriv('aes-256-gcm', cookieEncryptionKey(secret), Buffer.from(iv, 'base64url'));
        decipher.setAuthTag(Buffer.from(tag, 'base64url'));
        const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]);

        return JSON.parse(plaintext.toString('utf8')) as T;
    } catch {
        return null;
    }
}

export function buildCookieOptions(options?: Partial<CookieOptions>): CookieOptions {
    return {
        httpOnly: true,
        path: '/',
        sameSite: 'lax',
        secure: true,
        ...options
    };
}

export function parseProviderError(event: {url: URL}) {
    const code = event.url.searchParams.get('error');
    if (!code) return null;

    return error(400, {
        message: event.url.searchParams.get('error_description') ?? code
    });
}

export function absoluteUrl(event: {url: URL}, pathOrUrl: string) {
    if (/^https?:\/\//i.test(pathOrUrl)) return pathOrUrl;
    return new URL(pathOrUrl, event.url).toString();
}

export function internalRedirectPath(event: {url: URL}, pathOrUrl: string | undefined, fallback = '/') {
    if (!pathOrUrl) return fallback;

    try {
        const url = new URL(pathOrUrl, event.url);
        if (url.origin !== event.url.origin) return fallback;

        return `${url.pathname}${url.search}${url.hash}`;
    } catch {
        return fallback;
    }
}

export function validateIdTokenClaims(
    claims: OIDCUserClaims,
    nonce: string | undefined,
    clientId?: string,
    trustedAudiences: string[] = [],
    requireNonce = true
) {
    if (!Number.isFinite(claims.exp)) {
        throw error(401, {message: 'id_token expiration is required'});
    }
    if (!Number.isFinite(claims.iat)) {
        throw error(401, {message: 'id_token issued-at time is required'});
    }
    if (requireNonce && claims.nonce !== nonce) {
        throw error(401, {message: 'Invalid id_token nonce'});
    }
    if (!claims.sub) {
        throw error(401, {message: 'id_token subject is required'});
    }
    if (clientId) {
        const audiences = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
        const trusted = new Set([clientId, ...trustedAudiences]);
        if (!audiences.includes(clientId) || audiences.some((audience) => !trusted.has(audience))) {
            throw error(401, {message: 'id_token contains an untrusted audience'});
        }
        if (claims.azp !== undefined && claims.azp !== clientId) {
            throw error(401, {message: 'Invalid id_token authorized party'});
        }
    }
}

export function validateRefreshedIdTokenClaims(previous: OIDCUserClaims, claims: OIDCUserClaims) {
    const normalizeAudience = (value: OIDCUserClaims['aud']) =>
        (Array.isArray(value) ? [...value] : value === undefined ? [] : [value]).sort();
    if (claims.sub !== previous.sub) throw error(401, {message: 'Refreshed id_token subject changed'});
    if (JSON.stringify(normalizeAudience(claims.aud)) !== JSON.stringify(normalizeAudience(previous.aud))) {
        throw error(401, {message: 'Refreshed id_token audience changed'});
    }
    if (claims.azp !== previous.azp)
        throw error(401, {
            message: 'Refreshed id_token authorized party changed'
        });
    if (claims.auth_time !== undefined && claims.auth_time !== previous.auth_time) {
        throw error(401, {
            message: 'Refreshed id_token authentication time changed'
        });
    }
    if (claims.nonce !== undefined && claims.nonce !== previous.nonce) {
        throw error(401, {message: 'Invalid refreshed id_token nonce'});
    }
}

export function validateUserInfoSubject(claims: OIDCUserClaims, user: OIDCUserClaims | undefined) {
    if (user && user.sub !== claims.sub) {
        throw error(401, {
            message: 'UserInfo subject does not match id_token subject'
        });
    }
}

export function toPublicSession<TIdentity extends OIDCUserClaims = OIDCUserClaims>(
    session: OIDCSession<TIdentity> | null
): OIDCPublicSession<TIdentity> | null {
    if (!session) return null;

    return {
        isAuthenticated: true,
        identity: session.identity,
        groups: session.groups,
        scope: session.tokens.scope,
        expiresAt: session.tokens.expiresAt,
        issuer: session.issuer,
        sessionState: session.sessionState,
        sid: session.sid,
        sub: session.sub
    };
}
