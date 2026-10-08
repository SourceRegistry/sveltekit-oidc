import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';

const config = JSON.parse(readFileSync(new URL('../deno.json', import.meta.url), 'utf8'));
const entries = typeof config.exports === 'string' ? [config.exports] : Object.values(config.exports);
const deno = process.env.DENO_BIN ?? 'deno';

for (const entry of new Set(entries)) {
    const result = spawnSync(deno, ['info', '--json', '--unstable-byonm', '--unstable-sloppy-imports', entry], {
        cwd: new URL('..', import.meta.url),
        encoding: 'utf8'
    });

    if (result.error) throw result.error;
    if (result.status !== 0) {
        throw new Error(`Deno could not inspect ${entry}: ${result.stderr || result.stdout}`);
    }

    const graph = JSON.parse(result.stdout);
    const errors = graph.modules.filter((module) => module.error);
    if (errors.length) {
        for (const module of errors) console.error(`${entry}: ${module.error}`);
        process.exitCode = 1;
    } else {
        console.log(`JSR module graph resolves: ${entry}`);
    }
}
