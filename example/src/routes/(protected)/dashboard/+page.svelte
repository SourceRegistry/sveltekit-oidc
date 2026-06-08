<script lang="ts">
    import {useOIDC} from "@sourceregistry/sveltekit-oidc/client";
    import type {AppClaims} from "$lib/server/configurations/oidc.configuration";

    const oidc = useOIDC<AppClaims>();
</script>

<h1>
    Testing 123
</h1>

<!-- `claims.roles` is typed `string[]` end-to-end via the `transformClaims` in oidc.configuration.ts -->
<p>Roles: {oidc.claims?.roles.join(', ') ?? 'none'}</p>
