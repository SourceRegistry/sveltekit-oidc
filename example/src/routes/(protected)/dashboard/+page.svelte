<script lang="ts">
    import {useOIDC} from "@sourceregistry/sveltekit-oidc/client";

    // AppIdentity is inferred from App.Locals.oidc; no explicit type argument is needed.
    const oidc = useOIDC();
</script>

<h1>
    Testing 123
</h1>

<p>Signed in as {oidc.identity?.email ?? oidc.identity?.name ?? oidc.identity?.sub}</p>
<p>Roles: {oidc.identity?.roles.join(', ') || 'none'}</p>
