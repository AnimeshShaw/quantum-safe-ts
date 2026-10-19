#!/usr/bin/env node
/** Executable entry point: starts the quantum-safe MCP server (see `createServer`) on standard input and output. */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './index.js';

const server = createServer();
await server.connect(new StdioServerTransport());
