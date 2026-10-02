import { readFileSync } from 'node:fs';
import { fromHex } from '../src/utils.js';

/** Loads a committed fixture from tests/vectors/. */
export function vectors<T = any>(name: string): T {
  return JSON.parse(readFileSync(new URL(`../../../tests/vectors/${name}`, import.meta.url), 'utf8')) as T;
}

export const h = fromHex;
