import { SignatureKeyError } from '../errors/errors';

export type SignatureAlgorithm =
  'HMAC' | 'ECDSA' | 'RSASSA-PKCS1-v1_5' | 'RSA-PSS';

export class SignatureKeyHelper<
  T extends SignatureAlgorithm = SignatureAlgorithm,
> {
  /**
   * @param algorithm Algoritmo de firma a usar en esta instancia.
   */
  constructor(public algorithm: T) {}

  /**
   * Genera una key (o par de keys) adaptada al algoritmo configurado.
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
