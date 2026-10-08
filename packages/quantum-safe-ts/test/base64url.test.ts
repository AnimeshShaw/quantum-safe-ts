/**
 * `fromBase64Url` / `toBase64Url` take untrusted strings (JWT segments, keys from files and the network).
 * 1. Behaviour must be unchanged: padding is optional on input and never produced on output.
 * 2. A long run of `=` that is not at the end must be rejected in linear time. (The earlier `/=+$/` regular expression was quadratic on it,
 *    flagged by CodeQL as a polynomial regular expression on uncontrolled data.)
 */
import { describe, expect, it } from 'vitest';
import { InvalidArgumentError, fromBase64Url, toBase64Url } from '../src/core.js';

describe('base64url padding handling', () => {
  it('round-trips every length and never emits padding', () => {
    for (let n = 0; n <= 70; n++) {
      const data = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
      const s = toBase64Url(data);
      expect(s).not.toContain('=');
      expect(Array.from(fromBase64Url(s))).toEqual(Array.from(data));
    }
  });

  it('accepts correct padding, and none, for the same bytes', () => {
    expect(Array.from(fromBase64Url('aGk'))).toEqual([104, 105]);
    expect(Array.from(fromBase64Url('aGk='))).toEqual([104, 105]);
    expect(Array.from(fromBase64Url('aA'))).toEqual([104]);
    expect(Array.from(fromBase64Url('aA=='))).toEqual([104]);
    expect(Array.from(fromBase64Url(''))).toEqual([]);
  });

  it('rejects characters outside the alphabet, including in front of padding', () => {
    for (const bad of ['a b', 'aGk+', 'aGk/', 'a=Gk', '=aGk', 'aGk==x', 'éaGk']) {
      expect(() => fromBase64Url(bad), bad).toThrow(InvalidArgumentError);
    }
    expect(() => fromBase64Url(123 as unknown as string)).toThrow(InvalidArgumentError);
  });

  it('rejects a huge run of "=" followed by a character quickly (no quadratic backtracking)', () => {
    const hostile = '='.repeat(300_000) + 'a';
    const start = performance.now();
    expect(() => fromBase64Url(hostile)).toThrow(InvalidArgumentError);
    expect(performance.now() - start).toBeLessThan(500);
  });
});
