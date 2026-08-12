import { SignatureKeyError } from '../errors/errors';

export type SignatureAlgorithm =
  'HMAC' | 'ECDSA' | 'RSASSA-PKCS1-v1_5' | 'RSA-PSS';

/**
 * Class for generating signing keys for the supported signature algorithms.
 * Acts as the base class for `Signature`.
 */
export class SignatureKeyHelper<
  T extends SignatureAlgorithm = SignatureAlgorithm,
> {
  /**
   * @param algorithm Signature algorithm to use for this instance.
   */
  constructor(public algorithm: T) {}

  /**
   * Generates a key (or key pair) matching the configured algorithm.
   * Returns a single `CryptoKey` for HMAC, or a `CryptoKeyPair` for
   * ECDSA, RSASSA-PKCS1-v1_5 and RSA-PSS.
   *
   * @returns The generated `CryptoKey` or `CryptoKeyPair`, depending on
   * the algorithm.
   */
  public async key(): Promise<T extends 'HMAC' ? CryptoKey : CryptoKeyPair> {
    try {
      if (this.algorithm === 'HMAC') {
        return (await crypto.subtle.generateKey(
          { name: 'HMAC', hash: 'SHA-256' },
          true,
          ['sign', 'verify'],
        )) as T extends 'HMAC' ? CryptoKey : CryptoKeyPair;
      }

      if (this.algorithm === 'ECDSA') {
        return (await crypto.subtle.generateKey(
          { name: 'ECDSA', namedCurve: 'P-256' },
          true,
          ['sign', 'verify'],
        )) as T extends 'HMAC' ? CryptoKey : CryptoKeyPair;
      }

      if (
        this.algorithm === 'RSASSA-PKCS1-v1_5' ||
        this.algorithm === 'RSA-PSS'
      ) {
        return (await crypto.subtle.generateKey(
          {
            name: this.algorithm,
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
          },
          true,
          ['sign', 'verify'],
        )) as T extends 'HMAC' ? CryptoKey : CryptoKeyPair;
      }

      throw new Error(`Unsupported signature algorithm: ${this.algorithm}`);
    } catch (error) {
      throw new SignatureKeyError(error);
    }
  }
}
