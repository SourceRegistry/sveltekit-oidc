<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import type { Snippet } from 'svelte';

	import { setOIDCContext } from './context.js';
	import type { OIDCPublicSession, OIDCSessionManagementConfig } from '../server/index.js';

	type RedirectMode = 'login' | 'logout' | 'reload' | 'none';

	let {
		session = null,
		config,
		loginPath,
		logoutPath = '/auth/logout',
		checkSessionIntervalMs = 5000,
		revalidateIntervalMs = 30000,
		redirectOnExpired = 'login',
		redirectOnRevoked = 'login',
		redirectIfUnauthenticated = false,
		children
	}: {
		session?: OIDCPublicSession | null;
		config: OIDCSessionManagementConfig;
		loginPath?: string;
		logoutPath?: string;
		checkSessionIntervalMs?: number;
		revalidateIntervalMs?: number;
		redirectOnExpired?: RedirectMode;
		redirectOnRevoked?: RedirectMode;
		redirectIfUnauthenticated?: boolean;
		children?: Snippet;
	} = $props();

	let iframe = $state<HTMLIFrameElement | undefined>(undefined);
	let status = $state<'authenticated' | 'unauthenticated' | 'expired' | 'revoked'>('unauthenticated');
	let handledUnauthenticated = $state(false);

	const metadata = $derived(config.metadata);
	const resolvedLoginPath = $derived(loginPath ?? config.loginPath ?? '/auth/login');
	const iframeUrl = $derived(
		config.metadata.check_session_iframe ?? config.checkSessionIframe ?? undefined
	);
	const canMonitorIframe = $derived(
		Boolean(session?.isAuthenticated && session?.sessionState && iframeUrl)
	);

	const context = setOIDCContext({
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
		void goto(buildLoginUrl(returnTo), { invalidateAll: false });
	}

	async function revalidate() {
		await invalidateAll();
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
		status = isAuthenticated ? 'authenticated' : status === 'authenticated' ? 'unauthenticated' : status;
	});

	$effect(() => {
		if (!session?.isAuthenticated || !session.expiresAt) {
			return;
		}

		const timeoutMs = Math.max(0, session.expiresAt * 1000 - Date.now());
		const timer = window.setTimeout(() => {
			status = 'expired';
			void handleRedirect(redirectOnExpired);
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
