import {describe, expect, it} from 'vitest';

import {classifySessionMonitorEvent, classifySessionMonitorMessage} from './session-monitor.js';

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
