<script lang="ts">
    import {useOIDC} from "@sourceregistry/sveltekit-oidc/client";
    import type {AppClaims} from "$lib/server/configurations/oidc.configuration";

    const oidc = useOIDC<AppClaims>();
    let {data} = $props();
</script>

<h1>
    Testing 123
</h1>

<!-- `claims.roles` is typed `string[]` end-to-end via the `transformClaims` in oidc.configuration.ts -->
<p>Roles: {oidc.claims?.roles.join(', ') ?? 'none'}</p>

<!-- `data.permissions` comes from `requireAuth`'s typed `AppSession` (TSession),
     inferred from `transformSession` in oidc.configuration.ts -->
<p>Permissions: {data.permissions.join(', ') || 'none'}</p>
