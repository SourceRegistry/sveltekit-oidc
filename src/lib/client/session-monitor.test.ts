import {describe, expect, it} from 'vitest';

import {classifySessionMonitorMessage} from './session-monitor.js';

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
});
