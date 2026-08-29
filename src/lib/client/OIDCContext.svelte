<script lang="ts" module>
    import type {
        OIDCPublicSession,
        OIDCSessionManagementConfig, OIDCUserClaims
    } from '../server/index.js';
</script>

<script lang="ts" generics="TIdentity extends OIDCUserClaims = OIDCUserClaims">
    import {beforeNavigate, invalidate, invalidateAll} from '$app/navigation';
    import {onDestroy, tick} from 'svelte';
    import type {Snippet} from 'svelte';

    import {setOIDCContext} from './context.js';
	import {getIdlePhase, normalizeIdleDuration} from './idle.js';
    import {classifySessionMonitorEvent} from './session-monitor.js';

	type RedirectMode = 'login' | 'logout' | 'provider-logout' | 'reload' | 'none';

    type OIDCClientDebugEvent = {
        type: string;
        details?: Record<string, unknown>;
    };

    let {
        session = null,
        config,
        loginPath,
        logoutPath,
        checkSessionIntervalMs = 5000,
        monitorSession = true,
        revalidateIntervalMs = 0,
        renewalLeadTimeMs = 5000,
        redirectOnExpired = 'login',
        redirectOnRevoked = 'login',
        redirectIfUnauthenticated = false,
        idleTimeoutMs = 0,
		redirectOnIdle = 'provider-logout',
        idleEvents = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'wheel'],
        idleActivityThrottleMs = 1000,
        idleWarningMs = 0,
        idleWarning,
        heartbeatUrl,
        heartbeatIntervalMs = 60_000,
        onDebug,
        children
    }: {
        session?: OIDCPublicSession<TIdentity> | null;
        config: OIDCSessionManagementConfig;
        loginPath?: string;
        logoutPath?: string;
        checkSessionIntervalMs?: number;
        monitorSession?: boolean;
        revalidateIntervalMs?: number;
        renewalLeadTimeMs?: number;
        redirectOnExpired?: RedirectMode;
        redirectOnRevoked?: RedirectMode;
        redirectIfUnauthenticated?: boolean;
        /** Milliseconds of no user activity before forcing redirectOnIdle. 0 disables idle tracking. */
        idleTimeoutMs?: number;
        redirectOnIdle?: RedirectMode;
        /** window events treated as activity; reset the idle timer, throttled by idleActivityThrottleMs. */
        idleEvents?: string[];
        idleActivityThrottleMs?: number;
        /**
         * How long before idleTimeoutMs to show idleWarning instead of redirecting immediately.
         * 0 (default) skips the warning and redirects at idleTimeoutMs, same as before.
         * Must be less than idleTimeoutMs.
         */
        idleWarningMs?: number;
        /** Rendered while the idle warning is active. Passed secondsRemaining plus stayLoggedIn/logout callbacks. */
        idleWarning?: Snippet<[{secondsRemaining: number; stayLoggedIn: () => void; logout: () => void}]>;
        /**
         * Server endpoint touched on activity to reset the *server-side* idle timer
         * (e.g. the identity service's session_idle_timeout). Undefined disables this —
         * revalidate()/stayLoggedIn() alone only reach the server when the access token
         * is near expiry, so without this the server session can idle out independently
         * of what this component shows.
         */
        heartbeatUrl?: string;
        /** Minimum gap between heartbeat requests while active. Match the server's own touch throttle. */
        heartbeatIntervalMs?: number;
        /** Receives token-safe lifecycle events for diagnosing session changes. */
        onDebug?: (event: OIDCClientDebugEvent) => void;
        children?: Snippet;
    } = $props();

    let sessionIframe = $state<HTMLIFrameElement | undefined>(undefined);
    let silentReauthenticationIframe = $state<HTMLIFrameElement | undefined>(undefined);
    let silentReauthenticationUrl = $state<string | undefined>(undefined);
    let silentReauthenticationTimeout: number | undefined;
    let status = $state<'authenticated' | 'unauthenticated' | 'expired' | 'revoked'>('unauthenticated');
    let revalidating = $state(false);
    let handledUnauthenticated = $state(false);
    let idleWarningVisible = $state(false);
    let idleSecondsRemaining = $state(0);
    let idleStayLoggedIn = () => {};
    let idleLogoutNow = () => {};
    let sessionExpiredDuringRevalidation = false;

    function debug(type: string, details: Record<string, unknown> | undefined = undefined) {
        onDebug?.({type, details});
    }

    const metadata = $derived(config.metadata);
    const resolvedLoginPath = $derived(loginPath ?? config.loginPath ?? '/auth/login');
    const resolvedLogoutPath = $derived(logoutPath ?? config.logoutPath ?? '/auth/logout');
    const iframeUrl = $derived(
        config.metadata.check_session_iframe ?? config.checkSessionIframe ?? undefined
    );
    const canMonitorIframe = $derived(
        Boolean(monitorSession && session?.isAuthenticated && session?.sessionState && iframeUrl)
    );
	const effectiveIdleTimeoutMs = $derived(normalizeIdleDuration(idleTimeoutMs));
	const effectiveIdleWarningMs = $derived(normalizeIdleDuration(idleWarningMs));
	const effectiveIdleActivityThrottleMs = $derived(normalizeIdleDuration(idleActivityThrottleMs, 1000));
	const effectiveHeartbeatIntervalMs = $derived(normalizeIdleDuration(heartbeatIntervalMs, 60_000));
	const idleActivityStorageKey = $derived(`sveltekit-oidc:activity:${config.issuer}:${config.clientId}`);

    const context = setOIDCContext<TIdentity>({
        get isAuthenticated() {
            return Boolean(session?.isAuthenticated);
        },
        get session() {
            return session;
        },
        get identity() {
            return session?.identity;
        },
        get groups() {
            return session?.groups ?? [];
        },
        get issuer() {
            return config.issuer;
        },
        get metadata() {
            return metadata;
        },
        get status() {
            return status;
        },
        get revalidating() {
            return revalidating;
        },
        login: (returnTo: string | undefined = undefined) => login(returnTo),
        logout,
        revalidate
    });

    void context;

    // SvelteKit navigation hooks are registered for the component lifetime.
    // Only intercept login redirects while a background revalidation is active.
    beforeNavigate(({to, cancel}) => {
        if (revalidating && to?.url.pathname.startsWith(resolvedLoginPath)) {
            debug('revalidation_redirected_to_login', {pathname: to.url.pathname});
            cancel();
            sessionExpiredDuringRevalidation = true;
        }
    });

    function buildLoginUrl(
        returnTo = `${window.location.pathname}${window.location.search}`,
        prompt: 'none' | undefined = undefined
    ) {
        const url = new URL(resolvedLoginPath, window.location.href);
        url.searchParams.set('returnTo', returnTo);
        if (prompt) url.searchParams.set('prompt', prompt);
        return `${url.pathname}${url.search}${url.hash}`;
    }

    async function logout(clearSessionOnly = false) {
        if (clearSessionOnly) {
            debug('local_session_logout_requested');
            // Session-monitor events must clear only this application's session.
            // Keep the flag in the URL because logoutHandler also supports callers
            // that do not send a form body.
            const url = new URL(resolvedLogoutPath, window.location.href);
            url.searchParams.set('clearSessionOnly', '1');

            await fetch(url, {
                method: 'POST',
                redirect: 'manual'
            });
            return;
        }

        // Provider logout can include an interactive confirmation and redirects.
        // A fetch would follow that flow in the background, leaving the provider
        // session intact and allowing the app to immediately sign in again.
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = resolvedLogoutPath;
        form.style.display = 'none';
        document.body.append(form);
        form.submit();
    }

	async function sendHeartbeat(): Promise<boolean> {
		if (!heartbeatUrl) return true;
        try {
            const response = await fetch(heartbeatUrl, {method: 'POST', credentials: 'same-origin'});
            if (!response.ok) {
                debug('heartbeat_failed', {status: response.status});
				if (response.status === 401 || response.status === 403) void handleRedirect('logout');
				return false;
            }
            debug('heartbeat_sent');
			return true;
        } catch (err) {
            debug('heartbeat_failed', {error: err instanceof Error ? err.message : String(err)});
			return false;
        }
    }

    function login(returnTo: string | undefined = undefined) {
        debug('login_redirect_requested', {returnTo: returnTo ?? `${window.location.pathname}${window.location.search}`});
        // loginPath is a plain +server.ts redirect endpoint, not a routable
        // page — use a full browser navigation, not SvelteKit's goto().
        window.location.href = buildLoginUrl(returnTo);
    }

    async function revalidate() {
        if (revalidating) {
            debug('revalidation_skipped_in_flight');
            return;
        }
        debug('revalidation_started', {expiresAt: session?.expiresAt});
        revalidating = true;

        // If the server redirects to the login path during a background
        // revalidation (e.g. session lost, HMR store reset), the component's
        // navigation hook records it so we can handle the redirect below.
        sessionExpiredDuringRevalidation = false;

        try {
            if (session?.revalidationDependency) {
                debug('revalidation_dependency_invalidated', {
                    dependency: session.revalidationDependency
                });
                await invalidate(session.revalidationDependency);
            } else {
                debug('revalidation_fallback_invalidated_all');
                await invalidateAll();
            }
        } finally {
            revalidating = false;
        }

        if (sessionExpiredDuringRevalidation) {
            status = 'expired';
            debug('revalidation_session_expired');
            void handleRedirect(redirectOnExpired);
        } else {
            debug('revalidation_completed', {isAuthenticated: Boolean(session?.isAuthenticated), expiresAt: session?.expiresAt});
        }
    }

    async function handleRedirect(mode: RedirectMode) {
        if (mode === 'none') {
            return;
        }
        if (mode === 'reload') {
            window.location.reload();
            return;
        }
        if (mode === 'logout') {
            await logout(true);
            window.location.reload();
            return;
        }
		if (mode === 'provider-logout') {
			await logout(false);
			return;
		}

        login();
    }

    async function finishSilentReauthentication(result: 'authenticated' | 'logged_out') {
        if (silentReauthenticationTimeout) {
            window.clearTimeout(silentReauthenticationTimeout);
            silentReauthenticationTimeout = undefined;
        }
        silentReauthenticationUrl = undefined;
        await revalidate();
        await tick();

        if (result === 'authenticated' && session?.isAuthenticated) {
            status = 'authenticated';
            debug('silent_reauthentication_completed', {sub: session.sub});
            return;
        }

        status = 'revoked';
        debug('silent_reauthentication_logged_out');
        await handleRedirect(redirectOnRevoked);
    }

    function startSilentReauthentication() {
        if (silentReauthenticationUrl) return;

        debug('silent_reauthentication_started');
        silentReauthenticationUrl = buildLoginUrl(
            `${window.location.pathname}${window.location.search}`,
            'none'
        );
        silentReauthenticationTimeout = window.setTimeout(() => {
            debug('silent_reauthentication_timed_out');
            void logout(true).then(() => finishSilentReauthentication('logged_out'));
        }, 30_000);
    }

    function handleSilentReauthenticationLoad() {
        if (!silentReauthenticationUrl || !silentReauthenticationIframe?.contentWindow) return;

        try {
            const documentElement = silentReauthenticationIframe.contentWindow.document.documentElement;
            const result = documentElement.dataset.oidcSilentReauth;
            if (result === 'authenticated' || result === 'logged_out') {
                void finishSilentReauthentication(result);
            }
        } catch {
            // The authorization request is currently displaying the cross-origin OP document.
        }
    }

    onDestroy(() => {
        if (silentReauthenticationTimeout) window.clearTimeout(silentReauthenticationTimeout);
    });

    $effect(() => {
        const isAuthenticated = Boolean(session?.isAuthenticated);
        // Suppress authenticated→unauthenticated transition while a revalidation is
        // in-flight — the effect re-runs once revalidating flips false with the
        // final session state, preventing a mid-refresh flicker.
        if (revalidating && !isAuthenticated) return;
        status = isAuthenticated ? 'authenticated' : status === 'authenticated' ? 'unauthenticated' : status;
    });

    let lastExpiresAt: number | undefined;
    let renewalAttemptedForExpiresAt: number | undefined;

    $effect(() => {
        if (!session?.isAuthenticated || !session.expiresAt) {
            return;
        }

        // If a prior revalidate already came back with the same (still-past)
        // expiresAt, the server couldn't refresh the token (e.g. no refresh
        // token available) — retrying immediately forever would spin-loop.
        // Treat that as a hard expiry instead of rescheduling.
        if (
            lastExpiresAt !== undefined &&
            session.expiresAt <= lastExpiresAt &&
            session.expiresAt * 1000 <= Date.now()
        ) {
            status = 'expired';
            debug('session_expired_after_failed_renewal', {expiresAt: session.expiresAt});
            void handleRedirect(redirectOnExpired);
            return;
        }
        lastExpiresAt = session.expiresAt;

        const expiresAt = session.expiresAt;
        const leadTimeMs = renewalAttemptedForExpiresAt === expiresAt ? 0 : renewalLeadTimeMs;
        const timeoutMs = Math.max(0, expiresAt * 1000 - Date.now() - leadTimeMs);
        const timer = window.setTimeout(async () => {
            debug('token_renewal_due', {expiresAt});
            // Silent revalidate first — server's maybeRefreshSession will refresh
            // the token if a valid refresh_token exists. Only redirect if the
            // session comes back unauthenticated after that.
            renewalAttemptedForExpiresAt = expiresAt;
            await revalidate();
            await tick();
            if (!session?.isAuthenticated) {
                status = 'expired';
                debug('token_renewal_left_session_unauthenticated');
                void handleRedirect(redirectOnExpired);
            }
        }, timeoutMs);

        return () => window.clearTimeout(timer);
    });

    $effect(() => {
        if (!session?.isAuthenticated || !revalidateIntervalMs) {
            return;
        }

        const timer = window.setInterval(() => {
            void revalidate();
        }, revalidateIntervalMs);

        return () => window.clearInterval(timer);
    });

    $effect(() => {
        if (!heartbeatUrl || !session?.isAuthenticated) {
            return;
        }

        let lastHeartbeatAt = 0;
		let heartbeatInFlight = false;

        function onActivity() {
            const now = Date.now();
			if (heartbeatInFlight || now - lastHeartbeatAt < effectiveHeartbeatIntervalMs) return;
            lastHeartbeatAt = now;
			heartbeatInFlight = true;
			void sendHeartbeat().finally(() => {
				heartbeatInFlight = false;
			});
        }

        for (const eventName of idleEvents) {
            window.addEventListener(eventName, onActivity, {passive: true});
        }

        return () => {
            for (const eventName of idleEvents) {
                window.removeEventListener(eventName, onActivity);
            }
        };
    });

    $effect(() => {
		if (!effectiveIdleTimeoutMs || !session?.isAuthenticated) {
            idleWarningVisible = false;
            return;
        }

		let timer: number | undefined;
		let lastActivityAt = Date.now();
		let lastLocalActivityAt = 0;
		let logoutTriggered = false;
		try {
			const sharedActivity = Number(window.localStorage.getItem(idleActivityStorageKey));
			if (Number.isFinite(sharedActivity)) lastActivityAt = Math.max(lastActivityAt, sharedActivity);
		} catch {
			// Storage can be denied in privacy modes; per-tab idle tracking still works.
		}

		function shareActivity(timestamp: number) {
			try {
				window.localStorage.setItem(idleActivityStorageKey, String(timestamp));
			} catch {
				// See storage-read fallback above.
			}
		}

		function schedule() {
			if (timer) window.clearTimeout(timer);
			const phase = getIdlePhase(
				lastActivityAt,
				Date.now(),
				effectiveIdleTimeoutMs,
				effectiveIdleWarningMs
			);
			idleSecondsRemaining = phase.secondsRemaining;
			if (phase.phase === 'idle') {
				if (!logoutTriggered) {
					logoutTriggered = true;
					idleWarningVisible = false;
					debug('idle_timeout_reached', {idleTimeoutMs: effectiveIdleTimeoutMs});
					void handleRedirect(redirectOnIdle);
				}
				return;
			}
			if (phase.phase === 'warning' && !idleWarningVisible) {
				idleWarningVisible = true;
				debug('idle_warning_shown', {idleWarningMs: effectiveIdleWarningMs});
			} else if (phase.phase === 'active') {
				idleWarningVisible = false;
			}
			const untilTransition = Math.max(1, (phase.nextTransitionAt ?? Date.now() + 1000) - Date.now());
			timer = window.setTimeout(schedule, phase.phase === 'warning' ? Math.min(1000, untilTransition) : untilTransition);
		}

        function onActivity() {
            // Once the warning is up, passive activity (e.g. moving the mouse while
            // reading the modal) must not silently dismiss it — only an explicit
            // stayLoggedIn() response should reset the timer.
            if (idleWarningVisible) return;
            const now = Date.now();
			if (now - lastLocalActivityAt < effectiveIdleActivityThrottleMs) return;
			lastLocalActivityAt = now;
            lastActivityAt = now;
			shareActivity(now);
			schedule();
        }

		function onSharedActivity(event: StorageEvent) {
			if (event.key !== idleActivityStorageKey) return;
			const timestamp = Number(event.newValue);
			if (!Number.isFinite(timestamp) || timestamp <= lastActivityAt) return;
			lastActivityAt = timestamp;
			logoutTriggered = false;
			schedule();
		}

		idleStayLoggedIn = () => {
            debug('idle_warning_dismissed_stay_logged_in');
			void (async () => {
				if (!(await sendHeartbeat())) return;
				await revalidate();
				await tick();
				if (!session?.isAuthenticated) return;
				lastActivityAt = Date.now();
				logoutTriggered = false;
				shareActivity(lastActivityAt);
				schedule();
			})();
        };
        idleLogoutNow = () => {
			if (timer) window.clearTimeout(timer);
            idleWarningVisible = false;
            void logout();
        };

		shareActivity(lastActivityAt);
		schedule();
        for (const eventName of idleEvents) {
            window.addEventListener(eventName, onActivity, {passive: true});
        }
		window.addEventListener('storage', onSharedActivity);
		document.addEventListener('visibilitychange', schedule);

        return () => {
			if (timer) window.clearTimeout(timer);
            for (const eventName of idleEvents) {
                window.removeEventListener(eventName, onActivity);
            }
			window.removeEventListener('storage', onSharedActivity);
			document.removeEventListener('visibilitychange', schedule);
        };
    });

    $effect(() => {
        if (session?.isAuthenticated) {
            handledUnauthenticated = false;
            return;
        }
        if (!redirectIfUnauthenticated || handledUnauthenticated) {
            return;
        }

        handledUnauthenticated = true;
        status = status === 'expired' || status === 'revoked' ? status : 'unauthenticated';
        void handleRedirect(status === 'revoked' ? redirectOnRevoked : redirectOnExpired);
    });

    $effect(() => {
        if (!canMonitorIframe || !iframeUrl || !sessionIframe) {
            return;
        }

        const targetOrigin = new URL(iframeUrl).origin;
        const poll = window.setInterval(() => {
            if (!sessionIframe?.contentWindow || !session?.sessionState) {
                return;
            }

            sessionIframe.contentWindow.postMessage(`${config.clientId} ${session.sessionState}`, targetOrigin);
        }, checkSessionIntervalMs);

        const onMessage = (event: MessageEvent) => {
            const result = classifySessionMonitorEvent(event, targetOrigin, sessionIframe?.contentWindow);
            if (result === 'error') {
                // `error` means the OP could not determine session state (for example,
                // transient storage or network denial). It is not proof of revocation.
                debug('iframe_session_error', {origin: event.origin});
                return;
            }
            if (result === 'changed') {
                debug('iframe_session_event', {result, origin: event.origin});
                startSilentReauthentication();
            }
        };

        window.addEventListener('message', onMessage);

        return () => {
            window.clearInterval(poll);
            window.removeEventListener('message', onMessage);
        };
    });
</script>

{#if canMonitorIframe && iframeUrl}
    <iframe
            id="oidc-session-monitor"
            bind:this={sessionIframe}
            title="OIDC session monitor"
            src={iframeUrl}
            hidden
            aria-hidden="true"
    ></iframe>
{/if}

{#if silentReauthenticationUrl}
    <iframe
            bind:this={silentReauthenticationIframe}
            title="OIDC silent re-authentication"
            src={silentReauthenticationUrl}
            onload={handleSilentReauthenticationLoad}
            hidden
            aria-hidden="true"
    ></iframe>
{/if}

{#if idleWarningVisible && idleWarning}
    {@render idleWarning({
        secondsRemaining: idleSecondsRemaining,
        stayLoggedIn: () => idleStayLoggedIn(),
        logout: () => idleLogoutNow()
    })}
{/if}

{@render children?.()}
