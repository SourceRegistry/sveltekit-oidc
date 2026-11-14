// JSR cannot publish Svelte components, so its root entry is the server API plus
// the context helpers. On npm the root entry is the client entry.
export * from './server/index.js';
export { getOIDCContext, useOIDC } from './client/context.js';
