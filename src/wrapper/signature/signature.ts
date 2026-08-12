import {
  SignatureKeyHelper,
  SignatureAlgorithm,
} from '../../helpers/SignatureKeyHelper';
import { Base64 } from '../../helpers/base64';
import { SignatureSignError, SignatureVerifyError } from '../../errors/errors';

export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * Class for signing and verifying data using multiple signature algorithms.
 * Supports HMAC, ECDSA, RSASSA-PKCS1-v1_5 and RSA-PSS with type-safe overloading.
 *
 * @example
 * const sig = new Signature('HMAC');
 * const key = await sig.key();
 * const signature = await sig.sign('message', key);
 * const isValid = await sig.verify('message', signature, key);
 */
export class Signature<
  T extends SignatureAlgorithm = SignatureAlgorithm,
> extends SignatureKeyHelper<T> {
  //
  // OVERLOADS
  //

  /**
   * @param buffer Text to sign.
   * @param key Private key (`CryptoKey`) or key pair (`CryptoKeyPair`).
   * @param hash Hash algorithm. Defaults to 'SHA-256'.
   * @returns The signature in Base64 format.
   */
  public async sign<U extends 'HMAC' | 'ECDSA'>(
    this: Signature<U>,
    buffer: string,
    key: CryptoKey | CryptoKeyPair,
    hash?: HashAlgorithm,
  ): Promise<string>;

  /**
   * @param buffer Text to sign.
   * @param key Private key (`CryptoKey`) or key pair (`CryptoKeyPair`).
   * @param hash Hash algorithm. Defaults to 'SHA-256'.
   * @param salt Salt length in bytes. Defaults to 32.
   * @returns The signature in Base64 format.
   */
  public async sign<U extends 'RSASSA-PKCS1-v1_5' | 'RSA-PSS'>(
    this: Signature<U>,
    buffer: string,
    key: CryptoKey | CryptoKeyPair,
    hash?: HashAlgorithm,
    salt?: number,
  ): Promise<string>;

  //
  // Implementation
  //
  public async sign(
    buffer: string,
    key: CryptoKey | CryptoKeyPair,
    hash: HashAlgorithm = 'SHA-256',
    salt: number = 32,
  ): Promise<string> {
    try {
      const data = new TextEncoder().encode(buffer);
      const signingKey = 'privateKey' in key ? key.privateKey : key;

      const resultadoBuffer = await crypto.subtle.sign(
        {
          name: this.algorithm,
          ...((this.algorithm === 'ECDSA' || this.algorithm === 'HMAC') && {
            hash,
          }),
          ...(this.algorithm === 'RSA-PSS' && { saltLength: salt }),
        },
        signingKey,
        data,
      );

      return Base64.bufferToBase64(resultadoBuffer);
    } catch (error) {
      throw new SignatureSignError(error);
    }
  }

  //
  // OVERLOADS
  //

  /**
   * @param buffer Original text (the same one that was signed).
   * @param signature Base64 signature obtained with `sign()`.
   * @param key Public key (`CryptoKey`) or key pair (`CryptoKeyPair`).
   * @param hash Hash algorithm. Defaults to 'SHA-256'.
   * @returns `true` if the signature is valid, `false` if it's invalid.
   */
  public async verify<U extends 'HMAC' | 'ECDSA'>(
    this: Signature<U>,
    buffer: string,
    signature: string,
    key: CryptoKey | CryptoKeyPair,
    hash?: HashAlgorithm,
  ): Promise<boolean>;

  /**
   * @param buffer Original text (the same one that was signed).
   * @param signature Base64 signature obtained with `sign()`.
   * @param key Public key (`CryptoKey`) or key pair (`CryptoKeyPair`).
   * @param hash Hash algorithm. Defaults to 'SHA-256'.
   * @param salt Salt length in bytes. Defaults to 32.
   * @returns `true` if the signature is valid, `false` if it's invalid.
   */
  public async verify<U extends 'RSASSA-PKCS1-v1_5' | 'RSA-PSS'>(
    this: Signature<U>,
    buffer: string,
    signature: string,
    key: CryptoKey | CryptoKeyPair,
    hash?: HashAlgorithm,
    salt?: number,
  ): Promise<boolean>;

  //
  // Implementation
  //

  public async verify(
    buffer: string,
    signature: string,
    key: CryptoKey | CryptoKeyPair,
    hash: HashAlgorithm = 'SHA-256',
    salt: number = 32,
  ): Promise<boolean> {
    try {
      const data = new TextEncoder().encode(buffer);
      const verifyKey = 'publicKey' in key ? key.publicKey : key;

      const signatureBytes = new Uint8Array(Base64.base64ToBuffer(signature));

      return await crypto.subtle.verify(
        {
          name: this.algorithm,
          ...((this.algorithm === 'ECDSA' || this.algorithm === 'HMAC') && {
            hash,
          }),
          ...(this.algorithm === 'RSA-PSS' && { saltLength: salt }),
        },
        verifyKey,
        signatureBytes,
        data,
      );
    } catch (error) {
      throw new SignatureVerifyError(error);
    }
  }
}
