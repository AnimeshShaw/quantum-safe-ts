#!/usr/bin/env node
// `pqc-mcp` is an alias of `quantum-safe-mcp`: the same MCP server over stdio.
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
// The server package exports only its entry and package.json, so locate it through package.json.
const server = resolve(dirname(require.resolve('quantum-safe-mcp/package.json')), 'dist', 'server.js');
await import(pathToFileURL(server).href);
