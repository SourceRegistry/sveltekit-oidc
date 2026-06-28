<script lang="ts" module>
    import type {
        OIDCPublicSession,
        OIDCSessionManagementConfig, OIDCUserClaims
    } from '../server/index.js';
</script>

<script lang="ts" generics="TClaims extends OIDCUserClaims = OIDCUserClaims">
    import {invalidateAll, beforeNavigate} from '$app/navigation';
    import {tick} from 'svelte';
    import type {Snippet} from 'svelte';

    import {setOIDCContext} from './context.js';

    type RedirectMode = 'login' | 'logout' | 'reload' | 'none';

    let {
        session = null,
        config,
        loginPath,
        logoutPath = '/auth/logout',
        checkSessionIntervalMs = 5000,
        monitorSession = true,
        revalidateIntervalMs = 30000,
        renewalLeadTimeMs = 5000,
        redirectOnExpired = 'login',
        redirectOnRevoked = 'login',
        redirectIfUnauthenticated = false,
        children
    }: {
        session?: OIDCPublicSession<TClaims> | null;
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
        children?: Snippet;
    } = $props();

    let iframe = $state<HTMLIFrameElement | undefined>(undefined);
    let status = $state<'authenticated' | 'unauthenticated' | 'expired' | 'revoked'>('unauthenticated');
    let revalidating = $state(false);
    let handledUnauthenticated = $state(false);

    const metadata = $derived(config.metadata);
    const resolvedLoginPath = $derived(loginPath ?? config.loginPath ?? '/auth/login');
    const iframeUrl = $derived(
        config.metadata.check_session_iframe ?? config.checkSessionIframe ?? undefined
    );
    const canMonitorIframe = $derived(
        Boolean(monitorSession && session?.isAuthenticated && session?.sessionState && iframeUrl)
    );

    const context = setOIDCContext<TClaims>({
        get isAuthenticated() {
            return Boolean(session?.isAuthenticated);
        },
        get session() {
            return session;
        },
        get user() {
            return session?.user;
        },
        get claims() {
            return session?.claims;
        },
        get groups() {
            return session?.groups ?? [];
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

    function buildLoginUrl(returnTo = `${window.location.pathname}${window.location.search}`) {
        return `${resolvedLoginPath}?returnTo=${encodeURIComponent(returnTo)}`;
    }

    async function logout(clearSessionOnly = false) {
        const body = new URLSearchParams();
        if (clearSessionOnly) {
            body.set('clearSessionOnly', '1');
        }

        await fetch(logoutPath, {
            method: 'POST',
            headers: {
                'content-type': 'application/x-www-form-urlencoded'
            },
            body
        });
    }

    function login(returnTo?: string) {
        // loginPath is a plain +server.ts redirect endpoint, not a routable
        // page — use a full browser navigation, not SvelteKit's goto().
        window.location.href = buildLoginUrl(returnTo);
    }

    async function revalidate() {
        if (revalidating) return;
        revalidating = true;

        // If the server redirects to the login path during a background
        // revalidation (e.g. session lost, HMR store reset), intercept the
        // SvelteKit router navigation so we can handle it through
        // handleRedirect instead of a jarring mid-page router transition.
        let sessionExpiredDuringRevalidation = false;
        const stopIntercept = beforeNavigate(({ to, cancel }) => {
            if (to?.url.pathname.startsWith(resolvedLoginPath)) {
                cancel();
                sessionExpiredDuringRevalidation = true;
            }
        });

        try {
            await invalidateAll();
        } finally {
            stopIntercept();
            revalidating = false;
        }

        if (sessionExpiredDuringRevalidation) {
            status = 'expired';
            void handleRedirect(redirectOnExpired);
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
            void handleRedirect(redirectOnExpired);
            return;
        }
        lastExpiresAt = session.expiresAt;

        const expiresAt = session.expiresAt;
        const leadTimeMs = renewalAttemptedForExpiresAt === expiresAt ? 0 : renewalLeadTimeMs;
        const timeoutMs = Math.max(0, expiresAt * 1000 - Date.now() - leadTimeMs);
        const timer = window.setTimeout(async () => {
            // Silent revalidate first — server's maybeRefreshSession will refresh
            // the token if a valid refresh_token exists. Only redirect if the
            // session comes back unauthenticated after that.
            renewalAttemptedForExpiresAt = expiresAt;
            await revalidate();
            await tick();
            if (!session?.isAuthenticated) {
                status = 'expired';
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
