import {error} from '@sveltejs/kit';
import {createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual} from 'node:crypto';

import type {CookieOptions, OIDCPublicSession, OIDCSession, OIDCUserClaims} from './types.js';

/** One cookie secret, or several for rotation: the first encrypts, all are tried when decrypting. */
export type CookieSecrets = string | readonly string[];

/**
 * What an encrypted value is for. It is bound into the ciphertext as additional
 * authenticated data, so a value issued for one purpose cannot be replayed as another.
 */
export type CookiePurpose = 'session' | 'session-reference' | 'state' | 'oauth-state';

/** Random tokens are base64url; anything else from a request is never used in a cookie name. */
const OAUTH_STATE_TOKEN = /^[A-Za-z0-9_-]{1,128}$/;

export function isOAuthStateToken(value: unknown): value is string {
    return typeof value === 'string' && OAUTH_STATE_TOKEN.test(value);
}

export function cookieSecretList(secret: CookieSecrets): readonly string[] {
    return typeof secret === 'string' ? [secret] : secret;
}

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

export function verifySignedValue(value: string, secret: CookieSecrets) {
    const lastDot = value.lastIndexOf('.');
    if (lastDot === -1) return null;

    const payload = value.slice(0, lastDot);
    const actual = Buffer.from(value.slice(lastDot + 1), 'base64url');

    for (const candidate of cookieSecretList(secret)) {
        const expected = createHmac('sha256', candidate).update(payload).digest();
        if (expected.length === actual.length && timingSafeEqual(expected, actual)) return payload;
    }

    return null;
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
export function encodeOAuthState(
    token: string,
    returnTo: string | undefined,
    secret: CookieSecrets,
    restarts = 0
): string {
    if (!returnTo && !restarts) return token;
    return `v3.${serializeSignedCookie({token, returnTo, ...(restarts > 0 ? {restarts} : {})}, secret, 'oauth-state')}`;
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
 *
 * `restarts` counts how many times the callback has already restarted the
 * login for lack of a matching state cookie; it lets the callback stop
 * instead of looping when the cookie can never come back.
 *
 * The returned `token` is always a base64url string (or null), because it is
 * used to build the transaction cookie name.
 */
export function decodeOAuthState(
    raw: string | null | undefined,
    secret: CookieSecrets
): {token: string | null; returnTo?: string; restarts?: number} {
    if (!raw) return {token: null};
    if (raw.startsWith('v3.')) {
        const decoded = parseSignedCookie<{token?: unknown; returnTo?: unknown; restarts?: unknown}>(
            raw.slice(3),
            secret,
            'oauth-state'
        );
        if (!decoded || !isOAuthStateToken(decoded.token)) return {token: null};
        return {
            token: decoded.token,
            ...(typeof decoded.returnTo === 'string' ? {returnTo: decoded.returnTo} : {}),
            ...(Number.isInteger(decoded.restarts) && (decoded.restarts as number) > 0
                ? {restarts: decoded.restarts as number}
                : {})
        };
    }

    const separator = raw.indexOf('.');
    if (separator === -1) return {token: isOAuthStateToken(raw) ? raw : null};

    const token = raw.slice(0, separator);
    if (!isOAuthStateToken(token)) return {token: null};
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

function cookieAad(purpose: CookiePurpose) {
    return Buffer.from(`sveltekit-oidc:${purpose}`, 'utf8');
}

/**
 * Encrypts a payload with AES-256-GCM under the first cookie secret, binding
 * `purpose` as additional authenticated data (format `v3`).
 */
export function serializeSignedCookie(payload: unknown, secret: CookieSecrets, purpose: CookiePurpose) {
    const [current] = cookieSecretList(secret);
    if (!current) throw new TypeError('At least one cookie secret is required');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', cookieEncryptionKey(current), iv);
    cipher.setAAD(cookieAad(purpose));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return `v3.${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`;
}

/**
 * Decrypts a value written by serializeSignedCookie for the same `purpose`,
 * trying each cookie secret in turn. Values in the earlier `v2` format, which
 * carry no purpose, stay readable so existing sessions survive the upgrade;
 * new values are always written as `v3`.
 */
export function parseSignedCookie<T>(
    value: string | undefined,
    secret: CookieSecrets,
    purpose: CookiePurpose
): T | null {
    if (!value) return null;

    const parts = value.split('.');
    if (parts.length !== 4 || (parts[0] !== 'v3' && parts[0] !== 'v2')) return null;
    const [version, iv, tag, ciphertext] = parts;

    for (const candidate of cookieSecretList(secret)) {
        try {
            const decipher = createDecipheriv(
                'aes-256-gcm',
                cookieEncryptionKey(candidate),
                Buffer.from(iv, 'base64url')
            );
            if (version === 'v3') decipher.setAAD(cookieAad(purpose));
            decipher.setAuthTag(Buffer.from(tag, 'base64url'));
            const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]);

            return JSON.parse(plaintext.toString('utf8')) as T;
        } catch {
            // Wrong key, wrong purpose, or tampered value: try the next secret.
        }
    }

    return null;
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

    return event.url.searchParams.get('error_description') ?? code;
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
        // Dot segments can normalize to a leading '//' (e.g. '/.//evil.example'),
        // which browsers resolve as a protocol-relative URL to another host.
        if (url.pathname.startsWith('//')) return fallback;

        return `${url.pathname}${url.search}${url.hash}`;
    } catch {
        return fallback;
    }
}

/**
 * Checks `aud` and `azp` as for an ID token (OIDC Core 3.1.3.7 steps 3-5):
 * the client must be an audience, every other audience must be explicitly
 * trusted, and a present `azp` must be the client.
 */
export function findAudienceProblem(
    claims: {aud?: unknown; azp?: unknown},
    clientId: string,
    trustedAudiences: string[] = []
): 'audience' | 'authorized_party' | undefined {
    const audiences = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
    const trusted = new Set([clientId, ...trustedAudiences]);
    if (!audiences.includes(clientId) || audiences.some((audience) => !trusted.has(audience))) {
        return 'audience';
    }
    if (claims.azp !== undefined && claims.azp !== clientId) return 'authorized_party';
    return undefined;
}

export function validateIdTokenClaims(
    claims: OIDCUserClaims,
    nonce: string | undefined,
    clientId?: string,
    trustedAudiences: string[] = [],
    requireNonce = true
) {
    if (!Number.isFinite(claims.exp)) {
        throw error(401, 'id_token expiration is required');
    }
    if (!Number.isFinite(claims.iat)) {
        throw error(401, 'id_token issued-at time is required');
    }
    if (requireNonce && claims.nonce !== nonce) {
        throw error(401, 'Invalid id_token nonce');
    }
    if (!claims.sub) {
        throw error(401, 'id_token subject is required');
    }
    if (clientId) {
        const problem = findAudienceProblem(claims, clientId, trustedAudiences);
        if (problem === 'audience') throw error(401, 'id_token contains an untrusted audience');
        if (problem === 'authorized_party') throw error(401, 'Invalid id_token authorized party');
    }
}

export function validateRefreshedIdTokenClaims(previous: OIDCUserClaims, claims: OIDCUserClaims) {
    const normalizeAudience = (value: OIDCUserClaims['aud']) =>
        (Array.isArray(value) ? [...value] : value === undefined ? [] : [value]).sort();
    if (claims.sub !== previous.sub) throw error(401, 'Refreshed id_token subject changed');
    if (JSON.stringify(normalizeAudience(claims.aud)) !== JSON.stringify(normalizeAudience(previous.aud))) {
        throw error(401, 'Refreshed id_token audience changed');
    }
    if (claims.azp !== previous.azp)
        throw error(401, 'Refreshed id_token authorized party changed');
    if (claims.auth_time !== undefined && claims.auth_time !== previous.auth_time) {
        throw error(401, 'Refreshed id_token authentication time changed');
    }
    if (claims.nonce !== undefined && claims.nonce !== previous.nonce) {
        throw error(401, 'Invalid refreshed id_token nonce');
    }
}

export function validateUserInfoSubject(claims: OIDCUserClaims, user: OIDCUserClaims | undefined) {
    if (user && user.sub !== claims.sub) {
        throw error(401, 'UserInfo subject does not match id_token subject');
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
import '$app/server';
