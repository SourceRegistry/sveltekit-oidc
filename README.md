# sveltekit-oidc

[![npm version](https://img.shields.io/npm/v/@sourceregistry/sveltekit-oidc.svg)](https://www.npmjs.com/package/@sourceregistry/sveltekit-oidc)
[![license](https://img.shields.io/npm/l/@sourceregistry/sveltekit-oidc.svg)](LICENSE)
[![Svelte](https://img.shields.io/badge/Svelte-5-ff3e00.svg)](https://svelte.dev/)

OIDC authentication and session management for SvelteKit.

The library keeps three concerns separate:

- provider protocol data: validated ID token claims and optional UserInfo
- persisted authentication: tokens and the resolved application identity
- request data: application-owned authorization loaded once per request

It implements the protocol itself and does not depend on `openid-client`.

## Install

```sh
npm install @sourceregistry/sveltekit-oidc
```

## Configure

```ts
// src/lib/server/auth.ts
import {createOIDC} from '@sourceregistry/sveltekit-oidc/server';

type Identity = {
	sub: string;
	email?: string;
	name?: string;
	roles: string[];
	permissions?: string[];
};

type RequestData = {
	permissions: string[];
};

export const oidc = createOIDC<Identity, RequestData>({
	issuer: 'https://identity.example.com',
	clientId: process.env.OIDC_CLIENT_ID!,
	clientSecret: process.env.OIDC_CLIENT_SECRET!,
	clientAuthMethod: 'client_secret_basic',
	cookieSecret: process.env.OIDC_COOKIE_SECRET!,
	scope: ['openid', 'profile', 'email', 'offline_access'],

	resolveIdentity: ({idTokenClaims, userInfo}) => ({
		sub: idTokenClaims.sub,
		email: userInfo?.email ?? idTokenClaims.email,
		name: userInfo?.name ?? idTokenClaims.name,
		roles: Array.isArray(userInfo?.roles ?? idTokenClaims.roles)
			? ((userInfo?.roles ?? idTokenClaims.roles) as string[])
			: []
	}),

	beforeSessionPersist: async ({session, reason}) => {
		await synchronizeUser(session.identity, reason);
	},

	loadRequestData: async ({session, event}) => ({
		permissions: await loadPermissions(session.sub!, event)
	}),

	createPublicSession: ({base, data}) => ({
		...base,
		identity: {
			...base.identity,
			permissions: data?.permissions ?? []
		}
	})
});
```

The extension points have deliberately literal names:

| Extension point        | When it runs                                                    | Persisted               |
| ---------------------- | --------------------------------------------------------------- | ----------------------- |
| `resolveIdentity`      | After provider data is validated, on login and refresh          | Its result is persisted |
| `beforeSessionPersist` | Immediately before a login or refreshed session is written      | Side effects only       |
| `loadRequestData`      | Once while `handle` builds an authenticated request context     | Never                   |
| `createPublicSession`  | When `getPublicSession` or `toPublicSession` projects a session | Never                   |

Both login and refresh are explicit in the callback context:

```ts
beforeSessionPersist: async ({session, reason}) => {
	if (reason === 'login') {
		await recordLogin(session.identity);
	}
};
```

## SvelteKit hook

```ts
// src/hooks.server.ts
import {oidc} from '$lib/server/auth';

export const handle = oidc.handle;
```

For every request, `handle` exposes:

```ts
event.locals.oidc.session; // persisted OIDC session
event.locals.oidc.identity; // resolved identity
event.locals.oidc.data; // request-only application data
```

Type the locals directly from the configured instance:

```ts
// src/app.d.ts
import type {OIDCLocals} from '@sourceregistry/sveltekit-oidc/server';
import type {oidc} from '$lib/server/auth';

declare global {
	namespace App {
		interface Locals {
			oidc?: OIDCLocals<typeof oidc>;
		}
	}
}

export {};
```

## Routes

```ts
// src/routes/auth/login/+server.ts
import {oidc} from '$lib/server/auth';
export const GET = oidc.loginHandler();
```

```ts
// src/routes/auth/callback/+server.ts
import {oidc} from '$lib/server/auth';
export const GET = oidc.callbackHandler();
```

```ts
// src/routes/auth/logout/+server.ts
import {oidc} from '$lib/server/auth';
export const POST = oidc.logoutHandler();
```

```ts
// src/routes/auth/backchannel-logout/+server.ts
import {oidc} from '$lib/server/auth';
export const POST = oidc.backChannelLogoutHandler();
```

The underlying operations are also available directly when a route needs custom behavior:

- `login(event, options)`
- `handleCallback(event)`
- `logout(event, options)`
- `handleBackChannelLogout(event)`
- `getSession(event)`
- `requireAuth(event)`
- `clearSession(cookies)`

## Public session

Load a token-free session for the browser:

```ts
// src/routes/+layout.server.ts
import {oidc} from '$lib/server/auth';

export async function load(event) {
	return {
		session: oidc.toPublicSession(event.locals.oidc, event.depends),
		sessionManagement: await oidc.getSessionManagementConfig()
	};
}
```

`toPublicSession` projects the request context already loaded by `handle`. It does not read the
store, refresh tokens, or load application data again. `createPublicSession` receives both the
persisted session and `loadRequestData` result, but only exposes what the application explicitly
returns. `getPublicSession(event)` is available when the hook has not already loaded the context.

## Client context

```svelte
<script lang="ts">
	import { OIDCContext } from '@sourceregistry/sveltekit-oidc';
	let { data, children } = $props();
</script>

<OIDCContext session={data.session} config={data.sessionManagement}>
	{@render children()}
</OIDCContext>
```

```svelte
<script lang="ts">
	import { useOIDC } from '@sourceregistry/sveltekit-oidc';
	const oidc = useOIDC();
</script>

{#if oidc.isAuthenticated}
	<p>Signed in as {oidc.identity?.email ?? oidc.identity?.name}</p>
{/if}
```

`OIDCContext` supports local expiry handling, targeted SvelteKit revalidation,
`check_session_iframe` monitoring, and local or provider logout.

## Session stores

Without `sessionStore`, the encrypted session is stored in the cookie. For server-side sessions:

```ts
import type {OIDCSessionStore} from '@sourceregistry/sveltekit-oidc/server';

const sessionStore: OIDCSessionStore<Identity> = {
	get: (id) => redis.get(`session:${id}`),
	set: async (id, session) => {
		await redis.set(`session:${id}`, session);
	},
	delete: async (id) => {
		await redis.delete(`session:${id}`);
	}
};
```

Use a shared `backChannelLogoutStore` when back-channel logout must work across multiple instances.
The built-in `'memory'` stores are intended for local development or single-process deployments.

## Security behavior

- Authorization Code flow uses PKCE, state, and nonce.
- ID tokens are verified against provider JWKS and require matching issuer, audience, nonce, `exp`, and `iat`.
- UserInfo `sub` must match the validated ID token subject.
- Cookie sessions use authenticated encryption.
- Return and post-logout redirect values are restricted to same-origin paths.
- Local sessions have an eight-hour maximum lifetime by default.
- Refresh is automatic while a valid refresh token is available.
- Client authentication supports `none`, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, and `private_key_jwt`.

Application code can normalize provider-specific data in `resolveIdentity`, but cannot replace the
validated ID token claims used by the protocol implementation.
