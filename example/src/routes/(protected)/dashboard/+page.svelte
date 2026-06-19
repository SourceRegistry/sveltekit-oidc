<script lang="ts">
    import {useOIDC} from "@sourceregistry/sveltekit-oidc/client";

    // TClaims inferred from App.Locals.oidc — no explicit type arg needed
    const oidc = useOIDC();
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
