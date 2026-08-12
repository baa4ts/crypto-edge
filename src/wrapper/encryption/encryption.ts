import {
  EncryptionKeyHelper,
  EncryptAlgorithm,
} from '../../helpers/EncryptionKeyHelper';
import { Base64 } from '../../helpers/base64';
import {
  EncryptionDecryptError,
  EncryptionEncryptError,
} from '../../errors/errors';

/**
 * Utility for generating keys, encrypting and decrypting data using the
 * different AES modes supported by `SubtleCrypto`.
 * Supports AES-GCM, AES-CBC and AES-CTR with type-safe overloading.
 *
 * @example
 * const enc = new Encryption('AES-GCM');
 * const key = await enc.key();
 * const { ciphertext, iv } = await enc.encrypt('my secret text', key);
 * const text = await enc.decrypt(ciphertext, key, iv);
 */
export class Encryption<
  T extends EncryptAlgorithm = EncryptAlgorithm,
> extends EncryptionKeyHelper<T> {
  //
  // ENCRYPT OVERLOADS
  //

  /**
   * Encrypts a text with the given key (for GCM and CBC).
   *
   * @param buffer Text to encrypt.
   * @param key Key generated with `key()`.
   * @param iv Initialization vector. If not provided, a random one is generated.
   * @returns Object with the Base64 `ciphertext` and the Base64 `iv` used.
   */
  public async encrypt<U extends 'AES-GCM' | 'AES-CBC'>(
    this: Encryption<U>,
    buffer: string,
    key: CryptoKey,
    iv?: Uint8Array,
  ): Promise<{ ciphertext: string; iv: string }>;

  /**
   * Encrypts a text with the given key (for CTR).
   *
   * @param buffer Text to encrypt.
   * @param key Key generated with `key()`.
   * @param iv Initialization vector (used as the counter). If not provided, one is generated.
   * @param length Counter length in bits. Required for AES-CTR.
   * @returns Object with the Base64 `ciphertext` and the Base64 `iv` used.
   */
  public async encrypt<U extends 'AES-CTR'>(
    this: Encryption<U>,
    buffer: string,
    key: CryptoKey,
    iv?: Uint8Array,
    length?: number,
  ): Promise<{ ciphertext: string; iv: string }>;

  //
  // ENCRYPT Implementation
  //

  public async encrypt(
    buffer: string,
    key: CryptoKey,
    iv?: Uint8Array,
    length?: number,
  ): Promise<{ ciphertext: string; iv: string }> {
    try {
      const data = new TextEncoder().encode(buffer);

      if (!iv) {
        iv = crypto.getRandomValues(
          new Uint8Array(this.algorithm === 'AES-GCM' ? 12 : 16),
        );
      }

      const params =
        this.algorithm === 'AES-CTR'
          ? { name: this.algorithm, counter: iv, length: length }
          : { name: this.algorithm, iv };

      const ciphertext = await crypto.subtle.encrypt(params, key, data);

      return {
        ciphertext: Base64.bufferToBase64(ciphertext),
        iv: Base64.bufferToBase64(iv.buffer as ArrayBuffer),
      };
    } catch (error) {
      throw new EncryptionEncryptError(error);
    }
  }
  //
  // DECRYPT OVERLOADS
  //

  /**
   * Decrypts a ciphertext with the key and iv used to encrypt it (for GCM and CBC).
   *
   * @param ciphertext Base64-encoded encrypted data, obtained from `encrypt()`.
   * @param key Same key used in `encrypt()`.
   * @param iv Same Base64 iv returned by `encrypt()`.
   * @returns The decrypted original text.
   */
  public async decrypt<U extends 'AES-GCM' | 'AES-CBC'>(
    this: Encryption<U>,
    ciphertext: string,
    key: CryptoKey,
    iv: string,
  ): Promise<string>;

  /**
   * Decrypts a ciphertext with the key and iv used to encrypt it (for CTR).
   *
   * @param ciphertext Base64-encoded encrypted data, obtained from `encrypt()`.
   * @param key Same key used in `encrypt()`.
   * @param iv Same Base64 iv returned by `encrypt()` (used as the counter).
   * @param length Counter length in bits. Defaults to 64.
   * @returns The decrypted original text.
   */
  public async decrypt<U extends 'AES-CTR'>(
    this: Encryption<U>,
    ciphertext: string,
    key: CryptoKey,
    iv: string,
    length?: number,
  ): Promise<string>;

  //
  // DECRYPT Implementation
  //

  public async decrypt(
    ciphertext: string,
    key: CryptoKey,
    iv: string,
    length: number = 64,
  ): Promise<string> {
    try {
      const ciphertextBuffer = Base64.base64ToBuffer(ciphertext);
      const ivBuffer = new Uint8Array(Base64.base64ToBuffer(iv));

      const params =
        this.algorithm === 'AES-CTR'
          ? { name: this.algorithm, counter: ivBuffer, length: length }
          : { name: this.algorithm, iv: ivBuffer };

      const decrypted = await crypto.subtle.decrypt(
        params,
        key,
        ciphertextBuffer,
      );

      return new TextDecoder().decode(decrypted);
    } catch (error) {
      throw new EncryptionDecryptError(error);
    }
  }

  /**
   * Generates a random Initialization Vector (IV) of the correct size for
   * the configured algorithm (12 bytes for GCM, 16 for CBC/CTR).
   *
   * @returns The newly generated IV.
   */
  public generateIV(): Uint8Array {
    return crypto.getRandomValues(
      new Uint8Array(this.algorithm === 'AES-GCM' ? 12 : 16),
    );
  }
}
