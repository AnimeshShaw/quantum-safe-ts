#!/usr/bin/env node
// `pqc-audit` is an alias of `quantum-safe-audit`: same scanner, same options, same exit codes.
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const cli = resolve(dirname(require.resolve('quantum-safe-audit')), 'cli.js');
await import(pathToFileURL(cli).href);
