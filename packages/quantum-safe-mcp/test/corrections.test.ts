/** Corrections found while documenting the MCP server. */
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { describe, expect, it } from 'vitest';
import { createServer, resolveInside } from '../src/index.js';

async function connect(root: string) {
  const server = createServer({ root });
  const client = new Client({ name: 'test', version: '0.0.0' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}
const payload = (r: unknown): any => {
  const res = r as { content: Array<{ text: string }>; isError?: boolean };
  return res.isError ? { error: res.content[0]!.text } : JSON.parse(res.content[0]!.text);
};

describe('the scanned repository cannot hide its own findings', () => {
  it('qs-audit-ignore comments in the code do not suppress findings in audit_path', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'qs-mcp-ignore-'));
    writeFileSync(
      join(dir, 'a.js'),
      "// qs-audit-ignore-file\nconst c = require('node:crypto');\n// qs-audit-ignore\nc.generateKeyPairSync('rsa', { modulusLength: 2048 });\n",
    );
    const client = await connect(dir);
    const out = payload(await client.callTool({ name: 'audit_path', arguments: { path: '.' } }));
    expect(out.findings.some((f: { rule: string }) => f.rule === 'QSJ001')).toBe(true);
  });
});

describe('resolveInside', () => {
  it('accepts an entry whose name starts with two dots and refuses real escapes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'qs-mcp-dots-'));
    mkdirSync(join(dir, '..cache'));
    expect(resolveInside(dir, '..cache')).toContain('..cache');
    expect(() => resolveInside(dir, '..')).toThrow(/outside/);
    expect(() => resolveInside(dir, '../')).toThrow();
  });
});
