<script lang="ts">
	import type { OIDCPublicSession } from '$lib/server/index.js';

	let { data }: { data: { enabled: boolean; session?: OIDCPublicSession | null } } = $props();
</script>

<section>
	<h1>Protected Example</h1>
	{#if !data.enabled}
		<p>The repository demo is not configured.</p>
	{:else}
		<p>This page is protected through the example route integration.</p>
		<pre>{JSON.stringify(data.session, null, 2)}</pre>
	{/if}
</section>
