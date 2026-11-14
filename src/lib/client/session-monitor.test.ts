import {describe, expect, it} from 'vitest';

import {
	classifySessionMonitorEvent,
	classifySessionMonitorMessage,
	createSessionMonitorGuard
} from './session-monitor.js';

describe('OIDC session-monitor messages', () => {
	it('recognizes standard OP iframe results', () => {
		expect(classifySessionMonitorMessage('changed')).toBe('changed');
		expect(classifySessionMonitorMessage('unchanged')).toBe('unchanged');
		expect(classifySessionMonitorMessage('error')).toBe('error');
	});

	it('ignores unrelated window messages', () => {
		expect(classifySessionMonitorMessage({status: 'changed'})).toBe('ignored');
		expect(classifySessionMonitorMessage('unknown')).toBe('ignored');
	});

	it('accepts results only from the configured OP iframe window and origin', () => {
		const iframeWindow = {};
		expect(
			classifySessionMonitorEvent(
				{data: 'changed', origin: 'https://identity.example', source: iframeWindow as Window},
				'https://identity.example',
				iframeWindow
			)
		).toBe('changed');
		expect(
			classifySessionMonitorEvent(
				{data: 'changed', origin: 'https://identity.example', source: {} as Window},
				'https://identity.example',
				iframeWindow
			)
		).toBe('ignored');
		expect(
			classifySessionMonitorEvent(
				{data: 'changed', origin: 'https://other.example', source: iframeWindow as Window},
				'https://identity.example',
				iframeWindow
			)
		).toBe('ignored');
	});
});

describe('createSessionMonitorGuard', () => {
	const memoryStorage = () => {
		const values = new Map<string, string>();
		return {
			getItem: (key: string) => values.get(key) ?? null,
			setItem: (key: string, value: string) => void values.set(key, value),
			removeItem: (key: string) => void values.delete(key)
		};
	};

	it('flags an unconfirmed change shortly after the monitor ended a session, once', () => {
		let time = 1_000_000;
		const guard = createSessionMonitorGuard(memoryStorage(), 'key', 60_000, () => time);

		guard.recordMonitorLogout();
		time += 30_000;

		expect(guard.consumeRecentMonitorLogout()).toBe(true);
		expect(guard.consumeRecentMonitorLogout()).toBe(false);
	});

	it('ignores a monitor logout older than the window', () => {
		let time = 1_000_000;
		const guard = createSessionMonitorGuard(memoryStorage(), 'key', 60_000, () => time);

		guard.recordMonitorLogout();
		time += 61_000;

		expect(guard.consumeRecentMonitorLogout()).toBe(false);
	});

	it('does nothing without storage or when storage throws', () => {
		const throwing = {
			getItem: () => {
				throw new Error('denied');
			},
			setItem: () => {
				throw new Error('denied');
			},
			removeItem: () => {
				throw new Error('denied');
			}
		};

		expect(createSessionMonitorGuard(undefined, 'key').consumeRecentMonitorLogout()).toBe(false);
		const guard = createSessionMonitorGuard(throwing, 'key');
		expect(() => guard.recordMonitorLogout()).not.toThrow();
		expect(guard.consumeRecentMonitorLogout()).toBe(false);
	});
});
