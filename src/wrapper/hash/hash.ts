import { HashError } from '../../errors/errors';

/**
 * Generates a hex-encoded hash of the given text using the Web Crypto API.
 *
 * @example
 * const digest = await Hash('hello world', 'SHA-256');
 *
 * @param buffer Text to hash.
 * @param algorithm Hash algorithm (SHA-1/SHA-256/SHA-384/SHA-512).
 * @returns The generated hash in hexadecimal.
 */
export const Hash = async (
  buffer: string,
  algorithm: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512',
): Promise<string> => {
  try {
    const data = new TextEncoder().encode(buffer);

    const hashBuffer = await crypto.subtle.digest(algorithm, data);

    return [...new Uint8Array(hashBuffer)]
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  } catch (error) {
    throw new HashError(error);
  }
};
