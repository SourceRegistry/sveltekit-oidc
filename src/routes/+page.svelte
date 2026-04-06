<script lang="ts">
	import type { OIDCPublicSession } from '../lib/server/index.js';

	let { data }: { data: { demoOIDCConfigured?: boolean; session?: OIDCPublicSession | null } } = $props();
</script>

<svelte:head>
	<title>sveltekit-oidc demo</title>
</svelte:head>

<section>
	<h1>sveltekit-oidc</h1>
	<p>Showcase app for the packaged OIDC server helpers and frontend context.</p>

	{#if !data.demoOIDCConfigured}
		<p>
			Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, and `OIDC_COOKIE_SECRET` to enable the demo routes in
			this repository.
		</p>
	{:else}
		{#if data.session?.isAuthenticated}
			<p>Signed in as {data.session.user?.email ?? data.session.user?.name ?? data.session.sub}</p>
			<p>Groups: {data.session.groups.length ? data.session.groups.join(', ') : 'none'}</p>
			<p><a href="/protected">Open protected example</a></p>
			<form method="POST" action="/auth/logout">
				<button type="submit">Sign out</button>
			</form>
		{:else}
			<p>Demo OIDC is configured, but there is no active session.</p>
			<a href="/auth/login">Sign in</a>
		{/if}
	{/if}
</section>
