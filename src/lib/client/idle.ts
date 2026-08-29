export type IdlePhase = {
    phase: 'active' | 'warning' | 'idle';
    secondsRemaining: number;
    nextTransitionAt?: number;
};

export function normalizeIdleDuration(value: number, fallback = 0) {
    return Number.isFinite(value) && value > 0 ? value : fallback;
}

export function getIdlePhase(
    lastActivityAt: number,
    now: number,
    idleTimeoutMs: number,
    idleWarningMs: number
): IdlePhase {
    const deadline = lastActivityAt + idleTimeoutMs;
    if (now >= deadline) return {phase: 'idle', secondsRemaining: 0};
    const warningMs = idleWarningMs > 0 && idleWarningMs < idleTimeoutMs ? idleWarningMs : 0;
    const warningAt = deadline - warningMs;
    if (warningMs && now >= warningAt) {
        return {
            phase: 'warning',
            secondsRemaining: Math.max(0, Math.ceil((deadline - now) / 1000)),
            nextTransitionAt: deadline
        };
    }
    return {
        phase: 'active',
        secondsRemaining: Math.max(0, Math.ceil((deadline - now) / 1000)),
        nextTransitionAt: warningMs ? warningAt : deadline
    };
}
