import {describe, expect, it} from 'vitest';

import {asAuthorizationHeader} from './jwt.js';

describe('client_secret_basic', () => {
    it('form-encodes the client identifier and secret before Basic encoding', () => {
        const header = asAuthorizationHeader('client:id', 'secret with:colon');
        const decoded = Buffer.from(header.slice('Basic '.length), 'base64').toString('utf8');

        expect(decoded).toBe('client%3Aid:secret+with%3Acolon');
    });
});
