<script lang="ts">
	import OIDCContext from '$lib/client/OIDCContext.svelte';
	import type { OIDCPublicSession, OIDCSessionManagementConfig } from '$lib/server/index.js';

	let {
		data,
		children
	}: {
		data: {
			demoOIDCConfigured?: boolean;
			session?: OIDCPublicSession | null;
			sessionManagement?: OIDCSessionManagementConfig | null;
		};
		children: import('svelte').Snippet;
	} = $props();
</script>

{#if data.sessionManagement}
	<OIDCContext
		session={data.session}
		config={data.sessionManagement}
		logoutPath="/auth/logout"
		redirectIfUnauthenticated={false}
	>
		{@render children()}
	</OIDCContext>
{:else}
	{@render children()}
{/if}
