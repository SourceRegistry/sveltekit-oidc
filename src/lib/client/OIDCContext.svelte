<script lang="ts" module>
    import type {
        OIDCPublicSession,
        OIDCSessionManagementConfig, OIDCUserClaims
    } from '../server/index.js';
</script>

<script lang="ts" generics="TIdentity extends OIDCUserClaims = OIDCUserClaims">
    import {beforeNavigate, invalidate, invalidateAll} from '$app/navigation';
    import {tick} from 'svelte';
    import type {Snippet} from 'svelte';

    import {setOIDCContext} from './context.js';

    type RedirectMode = 'login' | 'logout' | 'reload' | 'none';

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
        /** Receives token-safe lifecycle events for diagnosing session changes. */
        onDebug?: (event: OIDCClientDebugEvent) => void;
        children?: Snippet;
    } = $props();

    let iframe = $state<HTMLIFrameElement | undefined>(undefined);
    let status = $state<'authenticated' | 'unauthenticated' | 'expired' | 'revoked'>('unauthenticated');
    let revalidating = $state(false);
    let handledUnauthenticated = $state(false);
    let sessionExpiredDuringRevalidation = false;

    function debug(type: string, details?: Record<string, unknown>) {
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
        login: (returnTo?: string) => login(returnTo),
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

    function buildLoginUrl(returnTo = `${window.location.pathname}${window.location.search}`) {
        return `${resolvedLoginPath}?returnTo=${encodeURIComponent(returnTo)}`;
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

    function login(returnTo?: string) {
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

        login();
    }

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
        if (!canMonitorIframe || !iframeUrl || !iframe) {
            return;
        }

        const targetOrigin = new URL(iframeUrl).origin;
        const poll = window.setInterval(() => {
            if (!iframe?.contentWindow || !session?.sessionState) {
                return;
            }

            iframe.contentWindow.postMessage(`${config.clientId} ${session.sessionState}`, targetOrigin);
        }, checkSessionIntervalMs);

        const onMessage = (event: MessageEvent) => {
            if (event.origin !== targetOrigin || typeof event.data !== 'string') {
                return;
            }
            if (event.data === 'changed' || event.data === 'error') {
                debug('iframe_session_event', {result: event.data, origin: event.origin});
                status = 'revoked';
                void logout(true).then(() => handleRedirect(redirectOnRevoked));
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
            bind:this={iframe}
            title="OIDC session monitor"
            src={iframeUrl}
            hidden
            aria-hidden="true"
    ></iframe>
{/if}

{@render children?.()}
