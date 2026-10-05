// Starts the aliased server and checks that it answers an MCP initialize request over stdio. Not shipped in the package.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const bin = fileURLToPath(new URL('./bin.js', import.meta.url));
const child = spawn(process.execPath, [bin], { stdio: ['pipe', 'pipe', 'inherit'] });
const timer = setTimeout(() => fail('no answer within 15 s'), 15000);
let out = '';

function fail(msg) {
  console.error('pqc-mcp test failed:', msg);
  child.kill();
  process.exit(1);
}

child.stdout.on('data', (d) => {
  out += d;
  if (!out.includes('\n')) return;
  clearTimeout(timer);
  const reply = JSON.parse(out.split('\n')[0]);
  child.kill();
  if (reply.id !== 1 || !reply.result || reply.result.serverInfo?.name !== 'quantum-safe') fail('unexpected reply: ' + out);
  console.log('pqc-mcp ok: server', reply.result.serverInfo.name, reply.result.serverInfo.version);
});
child.on('error', (e) => fail(String(e)));
child.stdin.write(
  JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'pqc-mcp-test', version: '0' } },
  }) + '\n',
);
