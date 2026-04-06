<script lang="ts">

    import {OIDCContext} from "@sourceregistry/sveltekit-oidc/client"

    const {data, children} = $props();

</script>

<OIDCContext session={data.session} config={data.config}>
    {@render children()}
    {JSON.stringify(data.config)}
</OIDCContext>
