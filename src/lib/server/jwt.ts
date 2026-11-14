import {error} from '@sveltejs/kit';
import {randomBytes} from 'node:crypto';
import {sign} from '@sourceregistry/node-jwt/promises';

import type {OIDCClientAssertionOptions, OIDCClientSecretJwtOptions, OIDCPrivateKeyJwtOptions} from './types.js';
import {base64UrlEncode} from './utils.js';

/** Longest provider error body kept in server logs. */
const PROVIDER_ERROR_LOG_LIMIT = 1000;

export type FetchJsonOptions = {
    fetch?: typeof fetch;
    /** Aborts the request (including reading the body) after this many ms. 0 disables the timeout. */
    timeoutMs?: number;
    /** Receives provider failure details, which are never placed in the thrown (user-visible) error. */
    log?: (message: string, details?: unknown) => void;
};

function isTimeout(err: unknown, signal: AbortSignal | undefined) {
    return Boolean(signal?.aborted) || (err as {name?: string} | null)?.name === 'TimeoutError';
}

/**
 * Fetches JSON from an OIDC provider endpoint.
 *
 * Errors thrown here end up on SvelteKit error pages, so they carry only a
 * generic message. The provider's status is kept (it drives the transient vs
 * permanent decisions in index.ts); statuses outside 4xx/5xx become 502, and a
 * timeout becomes 504. Details go to `options.log` instead.
 */
export async function fetchJson<T>(url: string, init?: RequestInit, options: FetchJsonOptions = {}): Promise<T> {
    const fetchImpl = options.fetch ?? fetch;
    const timeoutMs = options.timeoutMs ?? 0;
    const signal = timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined;
    const timedOut = () => {
        options.log?.(`OIDC request to '${url}' timed out after ${timeoutMs}ms`);
        return error(504, 'OIDC provider request timed out');
    };

    let response: Response;
    try {
        response = await fetchImpl(url, signal ? {...init, signal} : init);
    } catch (err) {
        if (isTimeout(err, signal)) throw timedOut();
        throw err;
    }

    if (!response.ok) {
        const body = await response.text().catch(() => '');
        options.log?.(
            `OIDC request to '${url}' failed with status ${response.status}`,
            body.slice(0, PROVIDER_ERROR_LOG_LIMIT)
        );
        const status = response.status >= 400 && response.status <= 599 ? response.status : 502;
        throw error(status, 'OIDC provider request failed');
    }

    try {
        return (await response.json()) as T;
    } catch (err) {
        if (isTimeout(err, signal)) throw timedOut();
        options.log?.(`OIDC request to '${url}' returned an invalid JSON response`, err);
        throw error(502, 'OIDC provider returned an invalid response');
    }
}

export function asAuthorizationHeader(clientId: string, clientSecret: string) {
    const encode = (value: string) => {
        const encoded = new URLSearchParams({value}).toString();
        return encoded.slice('value='.length);
    };
    return `Basic ${Buffer.from(`${encode(clientId)}:${encode(clientSecret)}`).toString('base64')}`;
}

export async function createClientSecretJwtAssertion(options: OIDCClientAssertionOptions & OIDCClientSecretJwtOptions) {
    if (!options.clientSecret) {
        throw error(500, 'clientSecret is required for client_secret_jwt');
    }

    const algorithm = options.algorithm ?? 'HS256';
    const now = Math.floor(Date.now() / 1000);

    return sign(
        {
            iss: options.clientId,
            sub: options.clientId,
            aud: options.tokenEndpoint,
            jti: base64UrlEncode(randomBytes(24)),
            iat: now,
            exp: now + (options.expiresInSeconds ?? 60)
        },
        options.clientSecret,
        {alg: algorithm, typ: 'JWT'}
    );
}

export async function createPrivateKeyJwtAssertion(options: OIDCClientAssertionOptions & OIDCPrivateKeyJwtOptions) {
    const algorithm = options.algorithm ?? 'RS256';
    const now = Math.floor(Date.now() / 1000);

    return sign(
        {
            iss: options.clientId,
            sub: options.clientId,
            aud: options.tokenEndpoint,
            jti: base64UrlEncode(randomBytes(24)),
            iat: now,
            exp: now + (options.expiresInSeconds ?? 60)
        },
        options.privateKey,
        {
            alg: algorithm,
            typ: 'JWT',
            ...(options.keyId ? {kid: options.keyId} : {})
        }
    );
}
import '$app/server';
