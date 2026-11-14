import {describe, expect, it, vi} from 'vitest';

import {asAuthorizationHeader, fetchJson} from './jwt.js';

describe('client_secret_basic', () => {
    it('form-encodes the client identifier and secret before Basic encoding', () => {
        const header = asAuthorizationHeader('client:id', 'secret with:colon');
        const decoded = Buffer.from(header.slice('Basic '.length), 'base64').toString('utf8');

        expect(decoded).toBe('client%3Aid:secret+with%3Acolon');
    });
});

describe('fetchJson', () => {
    const url = 'https://identity.example/token';

    it('keeps provider details out of the thrown error and passes them to the logger', async () => {
        const log = vi.fn();
        const fetchImpl = async () =>
            new Response('{"error":"invalid_client","error_description":"internal detail"}', {status: 401});

        const err = (await fetchJson(url, undefined, {fetch: fetchImpl, log}).catch((e: unknown) => e)) as {
            body: unknown;
        };

        expect(err).toMatchObject({status: 401, body: {message: 'OIDC provider request failed'}});
        expect(JSON.stringify(err.body)).not.toContain('internal detail');
        expect(JSON.stringify(err.body)).not.toContain(url);
        expect(log).toHaveBeenCalledWith(expect.stringContaining(url), expect.stringContaining('internal detail'));
    });

    it('maps non-error provider statuses to 502', async () => {
        const fetchImpl = async () => new Response(null, {status: 302, headers: {location: '/elsewhere'}});

        await expect(fetchJson(url, undefined, {fetch: fetchImpl})).rejects.toMatchObject({status: 502});
    });

    it('rejects a non-JSON success response with 502', async () => {
        const fetchImpl = async () => new Response('<html>proxy page</html>', {status: 200});

        await expect(fetchJson(url, undefined, {fetch: fetchImpl})).rejects.toMatchObject({
            status: 502,
            body: {message: 'OIDC provider returned an invalid response'}
        });
    });

    it('aborts a hanging provider request with 504 after the timeout', async () => {
        const fetchImpl = (_input: RequestInfo | URL, init?: RequestInit) =>
            new Promise<Response>((_resolve, reject) => {
                init?.signal?.addEventListener('abort', () => reject(init.signal!.reason));
            });

        await expect(fetchJson(url, undefined, {fetch: fetchImpl, timeoutMs: 20})).rejects.toMatchObject({
            status: 504,
            body: {message: 'OIDC provider request timed out'}
        });
    });

    it('does not attach a signal when the timeout is disabled', async () => {
        const fetchImpl = vi.fn(async () => new Response('{"ok":true}'));

        await expect(fetchJson(url, {method: 'GET'}, {fetch: fetchImpl, timeoutMs: 0})).resolves.toEqual({ok: true});
        expect(fetchImpl).toHaveBeenCalledWith(url, {method: 'GET'});
    });
});
