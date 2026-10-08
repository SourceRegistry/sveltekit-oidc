import { sveltekit } from '@sveltejs/kit/vite';
import adapter from '@sveltejs/adapter-auto';
import { defineConfig } from 'vitest/config';
import { relative, sep } from 'node:path';

export default defineConfig({
	plugins: [
		sveltekit({
			adapter: adapter(),
			compilerOptions: {
				runes: ({ filename }) => {
					const segments = relative(import.meta.dirname, filename).toLowerCase().split(sep);
					return segments.includes('node_modules') ? undefined : true;
				}
			}
		})
	],
	test: {
		exclude: ['**/.svelte-kit/**', '**/dist/**', '**/node_modules/**']
	}
});
