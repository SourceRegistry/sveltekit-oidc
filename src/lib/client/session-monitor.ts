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

type MonitorStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

/**
 * Detects a check_session_iframe that can never confirm a session, which is
 * what happens when the browser blocks the OP's cookies in a third-party
 * iframe: every check reports `changed`, silent re-authentication fails, and
 * each new login would be ended again moments later.
 *
 * When the monitor ends a session it records the time. If, within `windowMs`,
 * a later page sees `changed` before the iframe has ever reported `unchanged`,
 * the monitor is considered unreliable for this browser tab and should stop
 * acting on its results.
 */
export function createSessionMonitorGuard(
	storage: MonitorStorage | undefined,
	key: string,
	windowMs = 10 * 60_000,
	now: () => number = Date.now
) {
	return {
		recordMonitorLogout() {
			try {
				storage?.setItem(key, String(now()));
			} catch {
				// Storage can be unavailable in privacy modes; the guard is best-effort.
			}
		},
		/** Returns true, once, when a recent monitor logout makes an unconfirmed `changed` suspect. */
		consumeRecentMonitorLogout(): boolean {
			try {
				const recordedAt = Number(storage?.getItem(key));
				storage?.removeItem(key);
				return Number.isFinite(recordedAt) && recordedAt > 0 && now() - recordedAt < windowMs;
			} catch {
				return false;
			}
		}
	};
}
