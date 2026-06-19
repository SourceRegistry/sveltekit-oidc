# sveltekit-oidc

OIDC authentication helpers for SvelteKit with:

- server-side login, callback, logout, and session refresh flows
- token endpoint auth support for `none`, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, and `private_key_jwt`
- back-channel logout support through a revocation store
- signed cookie-backed sessions and PKCE/state protection
- a `handle` hook for attaching auth state to `event.locals`
- a small `OIDCContext` provider for client-side auth state and session lifecycle handling

## Install

```sh
npm install @sourceregistry/sveltekit-oidc
```

## Server Setup

```ts
// src/lib/server/auth.ts
import { createOIDC } from '@sourceregistry/sveltekit-oidc/server';

export const oidc = createOIDC({
	issuer: 'https://your-idp.example.com',
	clientId: process.env.OIDC_CLIENT_ID!,
	clientSecret: process.env.OIDC_CLIENT_SECRET!,
	cookieSecret: process.env.OIDC_COOKIE_SECRET!,
	clientAuthMethod: 'client_secret_basic',
	loginPath: '/auth/login',
	redirectPath: '/auth/callback',
	scope: 'openid profile email offline_access',
	backChannelLogoutStore: 'memory',
	cookieOptions: {
		secure: process.env.NODE_ENV === 'production'
	}
});
```

```ts
// src/hooks.server.ts
import { oidc } from '$lib/server/auth';

export const handle = oidc.handle;
```

```ts
// src/routes/auth/login/+server.ts
import { oidc } from '$lib/server/auth';

export const GET = oidc.loginHandler();
```

```ts
// src/routes/auth/callback/+server.ts
import { oidc } from '$lib/server/auth';

export const GET = oidc.callbackHandler({
	redirectTo: '/'
});
```

```ts
// src/routes/auth/logout/+server.ts
import { oidc } from '$lib/server/auth';

export const GET = oidc.logoutHandler();
export const POST = oidc.logoutHandler();
```

```ts
// src/routes/auth/backchannel-logout/+server.ts
import { oidc } from '$lib/server/auth';

export const POST = oidc.backChannelLogoutHandler();
```

## Actions

If you prefer form actions instead of dedicated routes:

```ts
// src/routes/+page.server.ts
import { oidc } from '$lib/server/auth';

export const actions = oidc.createActions();
```

## Load Session

```ts
// src/routes/+layout.server.ts
import { oidc } from '$lib/server/auth';

export async function load(event) {
	return {
		session: await oidc.getPublicSession(event),
		sessionManagement: await oidc.getSessionManagementConfig()
	};
}
```

## Client Setup

```html
<script lang="ts">
	import { OIDCContext } from '@sourceregistry/sveltekit-oidc';
	let { data } = $props();
</script>

<OIDCContext
	session={data.session}
	config={data.sessionManagement}
	logoutPath="/auth/logout"
	monitorSession={false}
	redirectIfUnauthenticated={false}
>
	<Account />
</OIDCContext>
```

```html
<!-- src/lib/Account.svelte -->
<script lang="ts">
	import { useOIDC } from '@sourceregistry/sveltekit-oidc';

	const oidc = useOIDC();
</script>

{#if oidc.isAuthenticated}
	<p>Signed in as {oidc.user?.email ?? oidc.user?.name ?? oidc.session?.sub}</p>
	<form method="POST" action="/auth/logout">
		<button type="submit">Sign out</button>
	</form>
{:else}
	<a href="/auth/login?returnTo=%2Faccount">Sign in</a>
{/if}
```

`OIDCContext` handles:

- local expiry redirects
- `check_session_iframe` polling when the provider advertises it
- periodic `invalidateAll()` revalidation so revoked server sessions are detected
- a client context for nested auth-aware components through `useOIDC()` / `getOIDCContext()`

Set `monitorSession={false}` when you want to keep the client context but leave remote session
revocation checks to your server-side guard or another mechanism. This disables
`check_session_iframe` polling without changing the provider metadata exposed through the context.

## Typed Custom Claims

`createOIDC` infers a `TClaims` type from whatever `transformClaims` / `transformUser` / `transformSession` return, and threads it through the session, `event.locals.oidc`, `OIDCPublicSession`, and the client context — no casts needed.

```ts
// src/lib/server/auth.ts
export const oidc = createOIDC({
	issuer: 'https://your-idp.example.com',
	clientId: process.env.OIDC_CLIENT_ID!,
	cookieSecret: process.env.OIDC_COOKIE_SECRET!,
	transformClaims: (claims) => ({
		...claims,
		roles: (claims.roles as string[]) ?? [],
		tenant: claims.tenant as string | undefined
	})
});
```

Wire `App.Locals` so `event.locals.oidc` is fully typed everywhere — `OIDCLocals` infers everything directly from the instance:

```ts
// src/app.d.ts
import type { OIDCLocals } from '@sourceregistry/sveltekit-oidc/server';
import { oidc } from '$lib/server/auth';

declare global {
	namespace App {
		interface Locals {
			oidc?: OIDCLocals<typeof oidc>;
		}
	}
}

export {};
```

Now `event.locals.oidc?.claims?.roles` is `string[]` and `?.tenant` is `string | undefined` in every hook, load function, and action — no separate type aliases needed.

When you need the claim type explicitly (e.g. in a Svelte component), use `OIDCInferClaims`:

```ts
import type { OIDCInferClaims } from '@sourceregistry/sveltekit-oidc/server';
import { oidc } from '$lib/server/auth';

type AppClaims = OIDCInferClaims<typeof oidc>;
```

`OIDCContext` is a generic component, but Svelte doesn't support passing explicit type arguments in markup — `TClaims` is inferred from the `session` prop instead. Since `data.session` comes from `oidc.getPublicSession(event)`, it's already typed `OIDCPublicSession<AppClaims> | null`, so the inference flows through automatically:

```html
<!-- src/routes/+layout.svelte -->
<script lang="ts">
	import { OIDCContext } from '@sourceregistry/sveltekit-oidc';
	let { data, children } = $props();
</script>

<OIDCContext session={data.session} config={data.sessionManagement}>
	{@render children()}
</OIDCContext>
```

```html
<!-- src/lib/Account.svelte -->
<script lang="ts">
	import { useOIDC } from '@sourceregistry/sveltekit-oidc';

	const auth = useOIDC(); // TClaims inferred from App.Locals.oidc
</script>

{#if auth.isAuthenticated}
	<p>Roles: {auth.claims?.roles.join(', ')}</p>
{/if}
```

If `transformClaims` (and friends) are omitted, `TClaims` defaults to `OIDCUserClaims` — existing setups keep working unchanged.

## Typed Custom Session

Backend apps commonly stash application-specific data on the session itself (e.g. `tenantId`, `permissions`) — not just inside `claims`/`user`. A second generic, `TSession`, is inferred from `transformSession`'s return type and threads through the session store, cookies, `event.locals.oidc`, and `handleCallback`'s result — again with no casts:

```ts
// src/lib/server/auth.ts
import { createOIDC, type OIDCSession } from '@sourceregistry/sveltekit-oidc/server';

type AppSession = OIDCSession<AppClaims> & {
	tenantId: string;
	permissions: string[];
};

export const oidc = createOIDC({
	issuer: 'https://your-idp.example.com',
	clientId: process.env.OIDC_CLIENT_ID!,
	cookieSecret: process.env.OIDC_COOKIE_SECRET!,
	transformClaims: (claims) => ({ ...claims, tenant: claims.tenant as string | undefined }),
	transformSession: (session): AppSession => ({
		...session,
		tenantId: session.claims?.tenant ?? 'default',
		permissions: session.user?.roles ?? []
	})
});
```

`app.d.ts` stays a one-liner — `OIDCLocals` picks up both `TClaims` and `TSession` from the instance:

```ts
// src/app.d.ts
import type { OIDCLocals } from '@sourceregistry/sveltekit-oidc/server';
import { oidc } from '$lib/server/auth';

declare global {
	namespace App {
		interface Locals {
			oidc?: OIDCLocals<typeof oidc>;
		}
	}
}

export {};
```

Now `event.locals.oidc?.session?.tenantId` is `string` and `?.permissions` is `string[]` everywhere — and `oidc.requireAuth(event)` / `handleCallback`'s `onsuccess` resolve to `AppSession` directly.

Use `OIDCInferClaims` / `OIDCInferSession` when you need the types explicitly:

```ts
import type { OIDCInferClaims, OIDCInferSession } from '@sourceregistry/sveltekit-oidc/server';
import { oidc } from '$lib/server/auth';

type AppClaims = OIDCInferClaims<typeof oidc>;
type AppSession = OIDCInferSession<typeof oidc>;
```

If `transformSession` is omitted, `TSession` defaults to `OIDCSession<TClaims>` — existing setups keep working unchanged.

## Example App

This repository now includes a runnable example under [src/routes](C:/Users/alexa/WebstormProjects/github.com/SourceRegistry/sveltekit-oidc/src/routes) and [src/hooks.server.ts](C:/Users/alexa/WebstormProjects/github.com/SourceRegistry/sveltekit-oidc/src/hooks.server.ts).

Set these environment variables to enable it:

- `OIDC_ISSUER`
- `OIDC_CLIENT_ID`
- `OIDC_COOKIE_SECRET`
- optional: `OIDC_CLIENT_SECRET`
- optional: `OIDC_SCOPE`
- optional: `OIDC_POST_LOGOUT_REDIRECT_URI`

## Notes

- `cookieSecret` should be a strong random secret and must stay stable across instances.
- `clockSkewSeconds` defaults to `30` and tolerates small clock drift between your app and the identity provider.
- `createInMemoryBackChannelLogoutStore()` is suitable for local development or single-instance deployments. Use Redis, SQL, or another shared store for production.
- The library validates `id_token` and `logout_token` values through `@sourceregistry/node-jwt` and provider JWKS metadata.
- `groups` are normalized onto the session from `groups` and `roles` claims when present.
- Use `transformClaims`, `transformUser`, and `transformSession` to project provider-specific claims into your own session shape.
- `check_session_iframe` monitoring only runs when `monitorSession` is enabled, the provider advertises that endpoint, and the session includes `session_state`.
- Refresh token handling is automatic when a valid refresh token is present.
- `event.locals.oidc` is attached by the hook; wire it in `app.d.ts` with `OIDCLocals<typeof oidc>` — see [Typed Custom Claims](#typed-custom-claims).
