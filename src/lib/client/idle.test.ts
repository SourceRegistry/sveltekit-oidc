import {describe, expect, it} from 'vitest';

import {getIdlePhase, normalizeIdleDuration} from './idle.js';

describe('idle session timing', () => {
    it('normalizes invalid durations without scheduling immediate logout', () => {
        expect(normalizeIdleDuration(Number.NaN)).toBe(0);
        expect(normalizeIdleDuration(-1)).toBe(0);
        expect(normalizeIdleDuration(1000)).toBe(1000);
    });

    it('derives active, warning, and idle phases from absolute time', () => {
        expect(getIdlePhase(1000, 2000, 10_000, 3000).phase).toBe('active');
        expect(getIdlePhase(1000, 8500, 10_000, 3000)).toMatchObject({
            phase: 'warning',
            secondsRemaining: 3
        });
        expect(getIdlePhase(1000, 11_000, 10_000, 3000)).toEqual({
            phase: 'idle',
            secondsRemaining: 0
        });
    });
});
