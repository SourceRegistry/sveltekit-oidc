export type OIDCSessionMonitorMessage = 'changed' | 'unchanged' | 'error' | 'ignored';

export function classifySessionMonitorMessage(data: unknown): OIDCSessionMonitorMessage {
	return data === 'changed' || data === 'unchanged' || data === 'error' ? data : 'ignored';
}
