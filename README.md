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

Requires SvelteKit 3 and Svelte 5. If your app uses `#lib` as in the examples below,
declare it in the app's `package.json`:

```json
{"imports":{"#lib":"./src/lib/index.js","#lib/*":"./src/lib/*"}}
```

The [API reference](https://sourceregistry.github.io/sveltekit-oidc/) lists every option and exported type.

## Configure

Declare the server-only configuration variables required by SvelteKit 3:

```ts
// src/env.ts
import {defineEnvVars} from '@sveltejs/kit/env';

export const variables = defineEnvVars({
    OIDC_ISSUER: {},
    OIDC_CLIENT_ID: {},
    OIDC_CLIENT_SECRET: {},
    OIDC_COOKIE_SECRET: {}
});
```

Set their values in your deployment environment. For local development, use an untracked `.env` file:

```dotenv
OIDC_ISSUER=https://identity.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_COOKIE_SECRET=replace-with-a-generated-secret
```

```ts
// src/lib/server/auth.ts
import {createOIDC} from '@sourceregistry/sveltekit-oidc/server';
import {OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_COOKIE_SECRET} from '$app/env/private';

type Identity = {
    sub: string;
    email?: string;
    name?: string;
    roles: string[];
};

export const oidc = createOIDC<Identity>({
    issuer: OIDC_ISSUER,
    clientId: OIDC_CLIENT_ID,
    clientSecret: OIDC_CLIENT_SECRET,
    clientAuthMethod: 'client_secret_basic',
    cookieSecret: OIDC_COOKIE_SECRET,
    scope: ['openid', 'profile', 'email', 'offline_access'],

    resolveIdentity: ({idTokenClaims, userInfo}) => ({
        sub: idTokenClaims.sub,
        email: userInfo?.email ?? idTokenClaims.email,
        name: userInfo?.name ?? idTokenClaims.name,
        roles: Array.isArray(userInfo?.roles ?? idTokenClaims.roles)
            ? ((userInfo?.roles ?? idTokenClaims.roles) as string[])
            : []
    })
});
```

Replace the placeholder cookie secret before starting the app. `cookieSecret` must contain at least
32 bytes of entropy. Generate one with:

```sh
openssl rand -base64 32
```

Discovery and protocol endpoints must use HTTPS by default. Set `allowInsecureHttp: true` only for
local development providers. `openid` is always included in the requested scope, and values in
`extraParams` cannot replace security-sensitive authorization parameters such as `state`, `nonce`,
PKCE, `redirect_uri`, or `client_id`.

If the client registration fixes an ID-token signing algorithm, pin it explicitly:

```ts
idTokenSigningAlgorithms: ['RS256'],
trustedIdTokenAudiences: ['https://api.example.com']
```

The client ID is always required in `aud`. `trustedIdTokenAudiences` permits only explicitly trusted
additional audience values; it does not replace the client ID.

Register an Authorization Code client with the provider. Allow the exact callback URL
`https://your-app.example/auth/callback`; it must match the app origin and `redirectPath`.
If you use provider logout, allow `https://your-app.example/` as a post-logout redirect, or
configure and register the path passed as `postLogoutRedirectUri`. Request a provider-supported
refresh-token scope such as `offline_access` if you need refresh tokens. Provider policies determine
whether a refresh token is issued and whether it rotates.

The extension points have deliberately literal names:

| Extension point        | When it runs                                                    | Persisted                                     |
| ---------------------- | --------------------------------------------------------------- | --------------------------------------------- |
| `resolveIdentity`      | After provider data is validated, on login and refresh          | Its result is persisted                       |
| `beforeSessionPersist` | Immediately before a login or refreshed session is written      | Returned session replaces it; `void` keeps it |
| `loadRequestData`      | Once while `handle` builds an authenticated request context     | Never                                         |
| `createPublicSession`  | When `getPublicSession` or `toPublicSession` projects a session | Never                                         |

Both login and refresh are explicit in the callback context. Returning a session from
`beforeSessionPersist` is what makes it the right place to provision or enrich application data —
e.g. upserting a user row — before the very first session for that user is persisted:

```ts
beforeSessionPersist: async ({session, reason}) => {
    if (reason !== 'login') return;
    const user = await upsertUser(session.identity);
    return {...session, identity: {...session.identity, ...user}};
};
```

`resolveIdentity` runs first and may only be able to _read_ application data (the user may not
exist yet on a first login). `beforeSessionPersist` runs next, right before the write, so a session
mutated or replaced there is the one every subsequent read of that session — including the result
returned from `handleCallback`/`callbackHandler`'s `onsuccess` — actually sees.

Use `loadRequestData` for request-specific authorization data, then `createPublicSession` if the
browser needs a safe subset of it. Neither callback is required for basic authentication. Never
include access, refresh, or ID tokens in the public session.

## SvelteKit hook

```ts
// src/hooks.server.ts
import {oidc} from '#lib/server/auth.js';

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
import type {oidc} from '#lib/server/auth.js';

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
import {oidc} from '#lib/server/auth.js';
export const GET = oidc.loginHandler();
```

```ts
// src/routes/auth/callback/+server.ts
import {oidc} from '#lib/server/auth.js';
export const GET = oidc.callbackHandler();
```

```ts
// src/routes/auth/logout/+server.ts
import {oidc} from '#lib/server/auth.js';
export const POST = oidc.logoutHandler();
```

```ts
// src/routes/auth/backchannel-logout/+server.ts
import {oidc} from '#lib/server/auth.js';
export const POST = oidc.backChannelLogoutHandler();
```

The back-channel route is optional. To use it, configure `backChannelLogoutStore`, register its
absolute URL with the provider, and ensure the provider advertises back-channel logout support.
Use a shared store when the app runs on multiple instances.

The underlying operations are also available directly when a route needs custom behavior:

- `login(event, options)`
- `handleCallback(event)`
- `logout(event, options)`
- `handleBackChannelLogout(event)`

### Request flow

```mermaid
sequenceDiagram
    participant Browser
    participant login as loginHandler
    participant callback as callbackHandler
    participant logout as logoutHandler
    participant bcl as backChannelLogoutHandler
    participant OP as OpenID Provider

    Browser->>login: GET /auth/login
    login->>login: create PKCE pair, state, nonce
    login-->>Browser: 302 redirect to OP authorize endpoint
    Browser->>OP: authenticate
    OP-->>Browser: 302 redirect with code & state

    Browser->>callback: GET /auth/callback?code&state
    callback->>OP: POST token endpoint (exchange code)
    OP-->>callback: id_token, access_token, optional refresh_token
    callback->>OP: GET JWKS when needed
    callback->>callback: verify id_token with JWKS
    callback->>OP: GET userinfo endpoint (optional)
    callback->>callback: resolveIdentity(idTokenClaims, userInfo)
    callback->>callback: beforeSessionPersist(session, reason:'login')
    Note over callback: a returned session here replaces<br/>what gets persisted and returned
    callback->>callback: write session (cookie or sessionStore)
    callback-->>Browser: onsuccess(event, result) or 302 redirect

    Browser->>logout: POST /auth/logout
    logout->>logout: clear persisted session
    logout-->>Browser: 302 redirect to OP end_session endpoint or local page

    OP->>bcl: POST /auth/backchannel-logout (logout_token)
    bcl->>OP: verify logout_token against JWKS
    bcl->>bcl: backChannelLogoutStore.revoke(sid/sub)
    bcl-->>OP: 200 OK
    Note over bcl: next getSession()/requireAuth() call<br/>for that sid/sub treats the session as revoked
```

`handle` (the SvelteKit hook) runs for every request, including these routes. It calls
`getSession`, which transparently refreshes an expiring session — running `resolveIdentity` and
`beforeSessionPersist` again with `reason: 'refresh'` — before exposing `event.locals.oidc`.

- `getSession(event)`
- `requireAuth(event)`
- `clearSession(cookies)`

## Public session

Load a token-free session for the browser:

```ts
// src/routes/+layout.server.ts
import {oidc} from '#lib/server/auth.js';

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

<OIDCContext
	session={data.session}
	config={data.sessionManagement}
	idleTimeoutMs={30 * 60 * 1000}
	idleWarningMs={60 * 1000}
>
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

Idle deadlines use absolute timestamps, synchronize activity across tabs, and remain correct after a
tab or device resumes from sleep. The default idle action performs provider logout; set
`redirectOnIdle="logout"` only when clearing the application session without ending the OP
session is intentional. `heartbeatUrl` is application-owned and should be a same-origin,
CSRF-protected endpoint that returns `401` or `403` when the session is no longer valid. Supply the
prop only after creating that endpoint; the example above does not require one.

When the OP iframe reports `changed`, the component first performs the Session Management 1.0
`prompt=none` authorization check in a hidden iframe. The login handler supplies the current ID token
as `id_token_hint`; a matching End-User refreshes the local session. A definitive login failure or
different End-User clears the matching local session. Temporary provider failures preserve it for
retry, and a callback from an older login cannot replace a newer local session. Applications using
the standard `loginHandler()` and `callbackHandler()` routes do not need an additional endpoint.

## Session stores

Without `sessionStore`, the encrypted session is stored in the cookie. The default maximum serialized
cookie size is 3800 bytes so oversized sessions fail explicitly instead of being silently truncated by
a browser or proxy. Use a server-side store for large tokens or identities:

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

For rotating refresh tokens in a multi-instance deployment, use **both** a shared `sessionStore`
and a distributed `refreshLock`. The lock serializes refresh and logout by session ID across
instances; after acquiring it, each instance rereads the shared store to find the current refresh
token. The built-in promise coalescing prevents duplicate refreshes within one process. Cookie-only
sessions cannot reliably coordinate a rotated refresh token across requests or instances because
there is no shared current token to reread:

```ts
const refreshLock = {
    runExclusive: <T>(sessionId: string, operation: () => Promise<T>) =>
        redlock.using([`oidc-refresh:${sessionId}`], 10_000, operation)
};
```

The lock's lease must remain valid for the complete token request and store write. Configure the
lock implementation and its timeout for your provider's response times.

## Security behavior

- Authorization Code flow uses PKCE, nonce, and an encrypted state value; each pending authorization
  transaction has its own cookie, so concurrent logins in separate tabs do not overwrite each other.
- Discovery metadata is bound to the configured issuer, and HTTPS is required unless explicitly
  disabled for local development.
- Initial ID tokens require matching issuer, client audience, nonce, `exp`, and `iat`. Refreshed ID
  tokens may omit nonce as allowed by OIDC Core, but must preserve subject, audiences, authorized
  party, and authentication time.
- UserInfo `sub` must match the validated ID token subject.
- Cookie sessions use authenticated encryption.
- Persisted sessions are checked against the configured client ID and issuer before use.
- A fresh login retires the previous server-stored session ID before issuing a new one.
- Silent re-authentication keeps a newer local login intact and retains a current session during temporary provider failures.
- Return and post-logout redirect values are restricted to same-origin paths.
- Local sessions have an eight-hour maximum lifetime by default.
- Refresh is automatic while a valid refresh token is available and is coalesced per session within a
  process. A temporary token-endpoint failure keeps a still-valid access token so the next request can
  retry. If the access token has expired, it returns a temporary 503 error but retains refresh credentials
  for a later retry. A rejected refresh token clears the session. If UserInfo is unavailable
  after a successful refresh, the rotated tokens are saved without carrying forward old UserInfo claims. The provider
  must return `expires_in` for expiry-driven automatic refresh; when it is omitted, the new access token's
  lifetime is unknown and the previous token's expiry is not reused.
  A rotated refresh token also does not inherit the previous refresh token's expiry.
- Back-channel logout tokens require the logout event, `iat`, `exp`, `jti`, and exactly one or both of
  `sid` and `sub`; `nonce` is rejected. A token with `sid` revokes only that session, while a token with
  `sub` alone revokes that user's sessions. Revocations expire and do not revoke later logins permanently.
- Local session clearing does not depend on provider discovery being available.
- Client authentication supports `none`, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, and `private_key_jwt`.

Application code can normalize provider-specific data in `resolveIdentity`, but cannot replace the
validated ID token claims used by the protocol implementation.
