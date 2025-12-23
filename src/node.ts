import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import type { BinaryLike } from './typings';

/**
 * Creates a new SHA-256 hash.
 *
 * @returns {import('node:crypto').Hash} A new Hash instance.
 */
export function createSha256() {
  return createHash('sha256');
}

/**
 * Computes the SHA-256 hash of the given data.
 *
 * @param {BinaryLike} data - The data to hash.
 * @returns {Uint8Array} The SHA-256 hash of the data.
 */
export function sha256(data: BinaryLike): Uint8Array {
  return createHash('sha256').update(data).digest();
}

/**
 * Computes the HMAC-SHA-256 of a message with a given key.
 *
 * @param {BinaryLike} key - The key for the HMAC.
 * @param {BinaryLike} message - The message to hash.
 * @returns {Uint8Array} The HMAC-SHA-256 of the message.
 */
export function hmacSha256(key: BinaryLike, message: BinaryLike): Uint8Array {
  return createHmac('sha256', key).update(message).digest();
}

/**
 * Compares two strings for equality in a timing-safe manner.
 *
 * @param {string} a - The first string to compare.
 * @param {string} b - The second string to compare.
 * @returns {boolean} True if the strings are equal, false otherwise.
 */
export function timeSafeCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export type * from './typings';
