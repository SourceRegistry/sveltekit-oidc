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
npm install sveltekit-oidc
```

## Server Setup

```ts
// src/lib/server/auth.ts
import {
	createInMemoryBackChannelLogoutStore,
	createOIDC
} from 'sveltekit-oidc/server';

export const oidc = createOIDC({
	issuer: 'https://your-idp.example.com',
	clientId: process.env.OIDC_CLIENT_ID!,
	clientSecret: process.env.OIDC_CLIENT_SECRET!,
	cookieSecret: process.env.OIDC_COOKIE_SECRET!,
	clientAuthMethod: 'client_secret_basic',
	loginPath: '/auth/login',
	redirectPath: '/auth/callback',
	scope: ['openid', 'profile', 'email', 'offline_access'],
	clockSkewSeconds: 30,
	fetchUserInfo: true,
	backChannelLogoutStore: createInMemoryBackChannelLogoutStore(),
	transformSession(session) {
		return {
			...session,
			groups: session.groups,
			user: session.user
				? {
						...session.user,
						groups: session.groups
					}
				: session.user
		};
	},
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
	import { OIDCContext } from 'sveltekit-oidc';
	let { data } = $props();
</script>

<OIDCContext
	session={data.session}
	config={data.sessionManagement}
	logoutPath="/auth/logout"
	redirectIfUnauthenticated={false}
>
	<Account />
</OIDCContext>
```

```html
<!-- src/lib/Account.svelte -->
<script lang="ts">
	import { useOIDC } from 'sveltekit-oidc';

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
- `check_session_iframe` monitoring only runs when the provider advertises that endpoint and the session includes `session_state`.
- Refresh token handling is automatic when a valid refresh token is present.
- `event.locals.oidc` is attached by the hook, but you should add your own `app.d.ts` augmentation in the consuming app for full typing.
