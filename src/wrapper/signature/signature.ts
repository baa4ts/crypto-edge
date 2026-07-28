import {
  SignatureKeyHelper,
  SignatureAlgorithm,
} from '../../helpers/SignatureKeyHelper';
import { Base64 } from '../../helpers/base64';
import { SignatureSignError, SignatureVerifyError } from '../../errors/errors';

export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * Clase para firmar y verificar datos usando multiples algoritmos de firma.
 * Soporta HMAC, ECDSA, RSASSA-PKCS1-v1_5 y RSA-PSS con type-safe overloading.
 *
 * @example
 * const sig = new Signature('HMAC');
 * const key = await sig.key();
 * const firma = await sig.sign('mensaje', key);
 * const valida = await sig.verify('mensaje', firma, key);
 */
export class Signature<
  T extends SignatureAlgorithm = SignatureAlgorithm,
> extends SignatureKeyHelper<T> {
  //
  // OVERLOADS
  //

  /**
   * @param buffer Texto a firmar.
   * @param key Clave privada (`CryptoKey`) o par de claves (`CryptoKeyPair`).
   * @param hash Algoritmo de hash. Por defecto 'SHA-256'.
   * @returns Firma en formato Base64.
   */
  public async sign<U extends 'HMAC' | 'ECDSA'>(
    this: Signature<U>,
    buffer: string,
    key: CryptoKey | CryptoKeyPair,
    hash?: HashAlgorithm,
  ): Promise<string>;

  /**
   * @param buffer Texto a firmar.
   * @param key Clave privada (`CryptoKey`) o par de claves (`CryptoKeyPair`).
   * @param hash Algoritmo de hash. Por defecto 'SHA-256'.
   * @param salt Largo del salt en bytes. Por defecto 32.
   * @returns Firma en formato Base64.
   */
  public async sign<U extends 'RSASSA-PKCS1-v1_5' | 'RSA-PSS'>(
    this: Signature<U>,
    buffer: string,
    key: CryptoKey | CryptoKeyPair,
    hash?: HashAlgorithm,
    salt?: number,
  ): Promise<string>;

  //
  // Implementacion
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
   * @param buffer Texto original (el mismo que se firmo).
   * @param signature Firma en formato Base64 obtenida con `sign()`.
   * @param key Clave publica (`CryptoKey`) o par de claves (`CryptoKeyPair`).
   * @param hash Algoritmo de hash. Por defecto 'SHA-256'.
   * @returns `true` si la firma es valida, `false` si es invalida.
   */
  public async verify<U extends 'HMAC' | 'ECDSA'>(
    this: Signature<U>,
    buffer: string,
    signature: string,
    key: CryptoKey | CryptoKeyPair,
    hash?: HashAlgorithm,
  ): Promise<boolean>;

  /**
   * @param buffer Texto original (el mismo que se firmo).
   * @param signature Firma en formato Base64 obtenida con `sign()`.
   * @param key Clave publica (`CryptoKey`) o par de claves (`CryptoKeyPair`).
   * @param hash Algoritmo de hash. Por defecto 'SHA-256'.
   * @param salt Largo del salt en bytes. Por defecto 32.
   * @returns `true` si la firma es valida, `false` si es invalida.
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
  // Implementacion
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
