export type OIDCSessionMonitorMessage = 'changed' | 'unchanged' | 'error' | 'ignored';

export function classifySessionMonitorMessage(data: unknown): OIDCSessionMonitorMessage {
	return data === 'changed' || data === 'unchanged' || data === 'error' ? data : 'ignored';
}

export function classifySessionMonitorEvent(
	event: Pick<MessageEvent, 'data' | 'origin' | 'source'>,
	expectedOrigin: string,
	expectedSource: unknown
): OIDCSessionMonitorMessage {
	if (event.origin !== expectedOrigin || !expectedSource || event.source !== expectedSource) {
		return 'ignored';
	}

	return classifySessionMonitorMessage(event.data);
}
