/**
 * LmsSigner: signatures verify with the library's own (RFC 8554-tested) verifier for every Winternitz parameter, one-time keys are never
 * reused (sequentially, after reopening, and across concurrent processes), the index is made durable before a signature exists, and any
 * damage to the state makes the signer refuse.
 */
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { InvalidArgumentError, Lms, SigningError, UnsupportedAlgorithmError, VerificationError } from '../src/index.js';
import { LmsSigner, assertNodeRuntime } from '../src/lms-signer.js';
import type { LmsKeyProtection } from '../src/lms-signer.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = fs.mkdtempSync(join(tmpdir(), 'qs-lms-signer-'));
let counter = 0;
const fresh = (): string => join(root, `key-${counter++}`);
const msg = (s: string): Uint8Array => new TextEncoder().encode(s);
const PLAIN = { unprotected: true } as const;
const indexOf = (sig: Uint8Array): number => new DataView(sig.buffer, sig.byteOffset).getUint32(4, false);

afterAll(() => fs.rmSync(root, { recursive: true, force: true }));
afterEach(() => vi.restoreAllMocks());

describe('signatures verify', () => {
  for (const w of [1, 2, 4, 8] as const) {
    it(`height 5, w = ${w}: every signature verifies and a different message does not`, () => {
      const signer = LmsSigner.create({ protection: PLAIN, directory: fresh(), height: 5, winternitz: w });
      const pk = signer.publicKey;
      expect(Lms.inspectPublicKey(pk)).toMatchObject({ levels: 1, treeHeight: 5, winternitz: w });
      expect(signer.parameterSet).toBe(`LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W${w}`);
      for (let n = 0; n < 3; n++) {
        const m = msg(`firmware image ${n}`);
        const sig = signer.sign(m);
        expect(Lms.isValid(pk, m, sig)).toBe(true);
        expect(indexOf(sig)).toBe(n);
        expect(Lms.isValid(pk, msg('another message'), sig)).toBe(false);
      }
    });
  }

  it('a flipped bit anywhere in a signature is rejected', () => {
    const signer = LmsSigner.create({ protection: PLAIN, directory: fresh(), height: 5, winternitz: 8 });
    const m = msg('flip');
    const sig = signer.sign(m);
    for (const at of [0, 5, 20, 100, sig.length - 40, sig.length - 1]) {
      const bad = sig.slice();
      bad[at] = (bad[at] ?? 0) ^ 1;
      let ok = true;
      try {
        ok = Lms.isValid(signer.publicKey, m, bad);
      } catch {
        ok = false;
      }
      expect(ok).toBe(false);
    }
    expect(() => Lms.verify(signer.publicKey, msg('x'), sig)).toThrow(VerificationError);
  });

  it('height 10 with w = 4 signs and verifies', () => {
    const signer = LmsSigner.create({ protection: PLAIN, directory: fresh(), height: 10, winternitz: 4 });
    expect(signer.capacity).toBe(1024);
    const m = msg('height ten');
    expect(Lms.isValid(signer.publicKey, m, signer.sign(m))).toBe(true);
  }, 60_000);
});

describe('state', () => {
  it('counts down, survives reopening and never reuses an index', () => {
    const dir = fresh();
    const a = LmsSigner.create({ protection: PLAIN, directory: dir, height: 5, winternitz: 2 });
    const seen = new Set<number>();
    seen.add(indexOf(a.sign(msg('1'))));
    seen.add(indexOf(a.sign(msg('2'))));
    expect(a.remaining).toBe(30);
    const b = LmsSigner.open(dir);
    expect(b.remaining).toBe(30);
    expect(Buffer.from(b.publicKey).equals(Buffer.from(a.publicKey))).toBe(true);
    // Two handles on one directory interleave without repeating an index.
    for (let i = 0; i < 6; i++) seen.add(indexOf((i % 2 ? a : b).sign(msg(`m${i}`))));
    expect(seen.size).toBe(8);
    expect([...seen].sort((x, y) => x - y)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(LmsSigner.open(dir).remaining).toBe(24);
  });

  it('refuses to sign once every one-time key is used, and says so', () => {
    const signer = LmsSigner.create({ protection: PLAIN, directory: fresh(), height: 5, winternitz: 2 });
    const used = new Set<number>();
    for (let i = 0; i < 32; i++) used.add(indexOf(signer.sign(msg(`m${i}`))));
    expect(used.size).toBe(32);
    expect(signer.remaining).toBe(0);
    expect(() => signer.sign(msg('one too many'))).toThrow(SigningError);
    expect(() => signer.sign(msg('one too many'))).toThrow(/used all/);
  });

  it('files are private to the owner (POSIX)', () => {
    if (process.platform === 'win32') return;
    const dir = fresh();
    LmsSigner.create({ protection: PLAIN, directory: dir, height: 5, winternitz: 2 });
    expect(fs.statSync(join(dir, 'key.json')).mode & 0o777).toBe(0o600);
    expect(fs.statSync(join(dir, 'tree.bin')).mode & 0o777).toBe(0o600);
  });

  it('refuses to overwrite an existing key', () => {
    const dir = fresh();
    LmsSigner.create({ protection: PLAIN, directory: dir, height: 5, winternitz: 2 });
    expect(() => LmsSigner.create({ protection: PLAIN, directory: dir, height: 5, winternitz: 2 })).toThrow(/already exists/);
  });

  it('rejects unsupported or invalid parameters', () => {
    expect(() => LmsSigner.create({ protection: PLAIN, directory: fresh(), height: 25 as never })).toThrow(UnsupportedAlgorithmError);
    expect(() => LmsSigner.create({ protection: PLAIN, directory: fresh(), height: 7 as never })).toThrow(InvalidArgumentError);
    expect(() => LmsSigner.create({ protection: PLAIN, directory: fresh(), height: 5, winternitz: 3 as never })).toThrow(InvalidArgumentError);
    expect(() => LmsSigner.create({ protection: PLAIN, directory: '' })).toThrow(InvalidArgumentError);
  });
});

describe('write-ahead: the index is durable before a signature exists', () => {
  it('a failed state write signs nothing and consumes nothing', () => {
    const signer = LmsSigner.create({ protection: PLAIN, directory: fresh(), height: 5, winternitz: 2 });
    vi.spyOn(fs, 'renameSync').mockImplementation(() => {
      throw new Error('disk full');
    });
    expect(() => signer.sign(msg('x'))).toThrow(SigningError);
    vi.restoreAllMocks();
    expect(signer.remaining).toBe(32);
    expect(indexOf(signer.sign(msg('x')))).toBe(0);
  });

  it('a failure after the reservation has already used the index, and releases no signature', () => {
    const signer = LmsSigner.create({ protection: PLAIN, directory: fresh(), height: 5, winternitz: 2 });
    vi.spyOn(crypto, 'randomBytes').mockImplementationOnce(() => {
      throw new Error('entropy source failed');
    });
    expect(() => signer.sign(msg('x'))).toThrow('entropy source failed');
    vi.restoreAllMocks();
    expect(signer.remaining).toBe(31); // the index is gone; it is never offered again
    expect(indexOf(signer.sign(msg('y')))).toBe(1);
  });

  it('refuses while the lock is held, then signs once it is gone', () => {
    const dir = fresh();
    const signer = LmsSigner.create({ protection: PLAIN, directory: dir, height: 5, winternitz: 2, lockTimeoutMs: 150 });
    fs.writeFileSync(join(dir, 'key.json.lock'), 'someone else');
    expect(() => signer.sign(msg('x'))).toThrow(/locked/);
    expect(signer.remaining).toBe(32);
    fs.unlinkSync(join(dir, 'key.json.lock'));
    expect(indexOf(signer.sign(msg('x')))).toBe(0);
    expect(fs.existsSync(join(dir, 'key.json.lock'))).toBe(false);
  });
});

describe('damaged state is refused', () => {
  const make = (): string => {
    const dir = fresh();
    LmsSigner.create({ protection: PLAIN, directory: dir, height: 5, winternitz: 2 });
    return dir;
  };

  it('a missing or unparsable key file', () => {
    const dir = make();
    fs.writeFileSync(join(dir, 'key.json'), '{ not json');
    expect(() => LmsSigner.open(dir)).toThrow(SigningError);
    fs.rmSync(join(dir, 'key.json'));
    expect(() => LmsSigner.open(dir)).toThrow(SigningError);
  });

  it('a counter that is not a count in range', () => {
    for (const next of [-1, 1.5, 33, 'zero', null]) {
      const dir = make();
      const key = JSON.parse(fs.readFileSync(join(dir, 'key.json'), 'utf8'));
      fs.writeFileSync(join(dir, 'key.json'), JSON.stringify({ ...key, next }));
      expect(() => LmsSigner.open(dir), String(next)).toThrow(SigningError);
    }
  });

  it('a tree file that was changed or truncated', () => {
    const dir = make();
    const tree = fs.readFileSync(join(dir, 'tree.bin'));
    const bad = Buffer.from(tree);
    bad[100] = (bad[100] ?? 0) ^ 1;
    fs.writeFileSync(join(dir, 'tree.bin'), bad);
    expect(() => LmsSigner.open(dir)).toThrow(/does not match/);
    fs.writeFileSync(join(dir, 'tree.bin'), tree.subarray(0, 64));
    expect(() => LmsSigner.open(dir)).toThrow(SigningError);
  });

  it('a state file swapped for another key’s', () => {
    const a = make();
    const b = make();
    const signer = LmsSigner.open(a);
    fs.copyFileSync(join(b, 'key.json'), join(a, 'key.json'));
    expect(() => signer.sign(msg('x'))).toThrow(/different key/);
  });

  it('a disposed signer', () => {
    const dir = fresh();
    const signer = LmsSigner.create({ protection: PLAIN, directory: dir, height: 5, winternitz: 2 });
    signer.dispose();
    expect(() => signer.sign(msg('x'))).toThrow(/disposed/);
    expect(() => signer.remaining).toThrow(/disposed/);
    expect(LmsSigner.open(dir).remaining).toBe(32); // nothing was consumed
  });
});

describe('runtime guard', () => {
  it('refuses outside Node.js and in browser-like global scopes', () => {
    expect(() => assertNodeRuntime({})).toThrow(UnsupportedAlgorithmError);
    expect(() => assertNodeRuntime({ process: { versions: { node: '22.0.0' } }, window: {} })).toThrow(/Browsers and Workers/);
    expect(() => assertNodeRuntime({ process: { versions: { node: '22.0.0' } }, WorkerGlobalScope: function () {} })).toThrow(
      UnsupportedAlgorithmError,
    );
    expect(() => assertNodeRuntime({ process: { versions: { node: '22.0.0' } } })).not.toThrow();
    expect(() => assertNodeRuntime()).not.toThrow(); // this test runs in Node
  });
});

describe('concurrent processes', () => {
  const dist = join(here, '..', 'dist', 'lms-signer.js');
  const built = fs.existsSync(dist);
  const script = join(root, 'signer.mjs');

  beforeAll(() => {
    if (!built) return;
    fs.writeFileSync(
      script,
      `import { LmsSigner } from ${JSON.stringify(new URL(`file://${dist.replace(/\\\\/g, '/')}`).href)};
const [, , dir, n, tag, keyHex] = process.argv;
const s = LmsSigner.open(dir, { lockTimeoutMs: 20000, ...(keyHex ? { key: Buffer.from(keyHex, 'hex') } : {}) });
const out = [];
for (let i = 0; i < Number(n); i++) {
  const m = new TextEncoder().encode(tag + ':' + i);
  out.push({ m: Buffer.from(m).toString('hex'), sig: Buffer.from(s.sign(m)).toString('hex') });
}
console.log(JSON.stringify(out));
`,
    );
  });

  const run = (dir: string, n: number, tag: string, keyHex = ''): Promise<{ m: string; sig: string }[]> =>
    new Promise((resolve, reject) => {
      const p = spawn(process.execPath, [script, dir, String(n), tag, keyHex], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      let err = '';
      p.stdout.on('data', (d) => (out += d));
      p.stderr.on('data', (d) => (err += d));
      p.on('close', (code) => (code === 0 ? resolve(JSON.parse(out) as { m: string; sig: string }[]) : reject(new Error(err))));
    });

  it.skipIf(!built)('four processes sign 8 messages each with a 32-leaf key and never share an index', async () => {
    const dir = fresh();
    const pk = LmsSigner.create({ protection: PLAIN, directory: dir, height: 5, winternitz: 2 }).publicKey;
    const all = (await Promise.all(['a', 'b', 'c', 'd'].map((t) => run(dir, 8, t)))).flat();
    expect(all).toHaveLength(32);
    const indices = all.map(({ sig }) => indexOf(Uint8Array.from(Buffer.from(sig, 'hex'))));
    expect(new Set(indices).size).toBe(32);
    for (const { m, sig } of all) {
      expect(Lms.isValid(pk, Uint8Array.from(Buffer.from(m, 'hex')), Uint8Array.from(Buffer.from(sig, 'hex')))).toBe(true);
    }
    expect(LmsSigner.open(dir).remaining).toBe(0);
  }, 120_000);

  it.skipIf(!built)('a key sealed under a supplied key is shared by processes that hold the key, and no more', async () => {
    const dir = fresh();
    const key = crypto.randomBytes(32);
    const pk = LmsSigner.create({ directory: dir, height: 5, winternitz: 2, protection: { key } }).publicKey;
    const all = (await Promise.all(['a', 'b'].map((t) => run(dir, 6, t, key.toString('hex'))))).flat();
    const indices = all.map(({ sig }) => indexOf(Uint8Array.from(Buffer.from(sig, 'hex'))));
    expect(new Set(indices).size).toBe(12);
    for (const { m, sig } of all) {
      expect(Lms.isValid(pk, Uint8Array.from(Buffer.from(m, 'hex')), Uint8Array.from(Buffer.from(sig, 'hex')))).toBe(true);
    }
    await expect(run(dir, 1, 'no-key')).rejects.toThrow(/sealed under a 32-byte key/);
  }, 120_000);
});

describe('protection: the seed is encrypted at rest', () => {
  const readKeyFile = (dir: string): Record<string, unknown> => JSON.parse(fs.readFileSync(join(dir, 'key.json'), 'utf8'));
  const writeKeyFile = (dir: string, obj: Record<string, unknown>): void => fs.writeFileSync(join(dir, 'key.json'), JSON.stringify(obj));
  const pass = { passphrase: 'correct horse battery staple', scryptLog2N: 14 } as const;

  it('requires an explicit choice', () => {
    expect(() => LmsSigner.create({ directory: fresh(), height: 5 } as never)).toThrow(/protection is required/);
    expect(() => LmsSigner.create({ directory: fresh(), height: 5, protection: {} as never })).toThrow(/protection is required/);
    expect(() =>
      LmsSigner.create({ directory: fresh(), height: 5, protection: { passphrase: 'x', unprotected: true } as never }),
    ).toThrow(/protection is required/);
    expect(() => LmsSigner.create({ directory: fresh(), height: 5, protection: { key: new Uint8Array(16) } })).toThrow(/32 bytes/);
    expect(() => LmsSigner.create({ directory: fresh(), height: 5, protection: { passphrase: 'x', scryptLog2N: 3 } })).toThrow(/scryptLog2N/);
  });

  it('a passphrase key stores no plain seed, opens only with the passphrase, and signs', () => {
    const dir = fresh();
    const a = LmsSigner.create({ directory: dir, height: 5, winternitz: 2, protection: pass });
    const file = readKeyFile(dir);
    expect(file.protection).toBe('passphrase');
    expect('seed' in file).toBe(false);
    expect(file.sealed).toBeTruthy();
    expect(file.kdf).toMatchObject({ name: 'scrypt', log2N: 14, r: 8, p: 1 });
    expect(() => LmsSigner.open(dir)).toThrow(/sealed under a passphrase/);
    expect(() => LmsSigner.open(dir, { passphrase: 'wrong' })).toThrow(/unsealed/);
    const b = LmsSigner.open(dir, { passphrase: pass.passphrase });
    const m = msg('sealed key');
    expect(Lms.isValid(a.publicKey, m, b.sign(m))).toBe(true);
    expect(indexOf(a.sign(m))).toBe(1);
  });

  it('a passphrase is compared after Unicode normalisation (NFC)', () => {
    const dir = fresh();
    const decomposed = `caf${String.fromCharCode(0x65, 0x301)}`;
    const composed = `caf${String.fromCharCode(0xe9)}`;
    LmsSigner.create({ directory: dir, height: 5, winternitz: 2, protection: { passphrase: decomposed, scryptLog2N: 14 } });
    expect(LmsSigner.open(dir, { passphrase: composed }).remaining).toBe(32);
  });

  it('a supplied key: right key signs, wrong key and no key are refused', () => {
    const dir = fresh();
    const key = new Uint8Array(crypto.randomBytes(32));
    LmsSigner.create({ directory: dir, height: 5, winternitz: 2, protection: { key } });
    expect(readKeyFile(dir).protection).toBe('key');
    expect(LmsSigner.open(dir, { key }).remaining).toBe(32);
    expect(() => LmsSigner.open(dir, { key: new Uint8Array(crypto.randomBytes(32)) })).toThrow(/unsealed/);
    expect(() => LmsSigner.open(dir)).toThrow(/32-byte key/);
    expect(() => LmsSigner.open(dir, { key: new Uint8Array(8) })).toThrow(/32-byte key/);
  });

  it('the caller key is not wiped by the signer', () => {
    const key = new Uint8Array(crypto.randomBytes(32));
    const copy = key.slice();
    const s = LmsSigner.create({ directory: fresh(), height: 5, winternitz: 2, protection: { key } });
    s.dispose();
    expect(key).toEqual(copy);
  });

  it('a counter edited without the key is refused, by a running signer and on open', () => {
    const cases: Array<{ protection: LmsKeyProtection; creds: { passphrase?: string; key?: Uint8Array } }> = [
      { protection: pass, creds: { passphrase: pass.passphrase } },
      { protection: { key: new Uint8Array(32).fill(7) }, creds: { key: new Uint8Array(32).fill(7) } },
      { protection: PLAIN, creds: {} },
    ];
    for (const { protection, creds } of cases) {
      const dir = fresh();
      const signer = LmsSigner.create({ directory: dir, height: 5, winternitz: 2, protection });
      signer.sign(msg('one'));
      writeKeyFile(dir, { ...readKeyFile(dir), next: 0 }); // an attempt to rewind by hand
      expect(() => signer.sign(msg('two'))).toThrow(/authentication code/);
      expect(() => signer.remaining).toThrow(/authentication code/);
      expect(() => LmsSigner.open(dir, creds)).toThrow(/authentication code/);
    }
  });

  it('a sealed seed moved to another key file is refused (it is bound to its header)', () => {
    const a = fresh();
    const b = fresh();
    LmsSigner.create({ directory: a, height: 5, winternitz: 2, protection: pass });
    LmsSigner.create({ directory: b, height: 5, winternitz: 2, protection: pass });
    writeKeyFile(b, { ...readKeyFile(b), sealed: readKeyFile(a).sealed, kdf: readKeyFile(a).kdf });
    expect(() => LmsSigner.open(b, { passphrase: pass.passphrase })).toThrow(/unsealed/);
  });

  it('a hostile key file cannot demand an unbounded scrypt cost, and an old development format is refused', () => {
    const dir = fresh();
    LmsSigner.create({ directory: dir, height: 5, winternitz: 2, protection: pass });
    const file = readKeyFile(dir) as { kdf: Record<string, unknown> };
    writeKeyFile(dir, { ...file, kdf: { ...file.kdf, log2N: 40 } });
    expect(() => LmsSigner.open(dir, { passphrase: pass.passphrase })).toThrow(/damaged or from an unknown format/);
    writeKeyFile(dir, { ...readKeyFile(dir), version: 1 });
    expect(() => LmsSigner.open(dir, { passphrase: pass.passphrase })).toThrow(/unknown format/);
  });
});
