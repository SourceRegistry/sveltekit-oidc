<script lang="ts">

    import {OIDCContext} from "@sourceregistry/sveltekit-oidc/client"

    const {data, children} = $props();

</script>

<!-- TClaims (AppClaims) is inferred from `data.session`'s type — no explicit
     type argument needed; Svelte components don't support that syntax in markup. -->
<OIDCContext session={data.session} config={data.config}>
    {@render children()}
    {JSON.stringify(data.config)}
</OIDCContext>
