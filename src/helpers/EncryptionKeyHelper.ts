import { EncryptionKeyError } from '../errors/errors';

export type EncryptAlgorithm = 'AES-GCM' | 'AES-CBC' | 'AES-CTR';

/**
 * Class for managing symmetric cryptographic keys for encryption.
 * Supports generating new random keys or importing them from raw bytes.
 *
 * @example
 * const enc = new EncryptionKeyHelper('AES-GCM');
 * const key = await enc.key(); // Generates a 256-bit key
 * const bytes = await enc.export({ key });
 * const importedKey = await enc.key(bytes); // Imports the key
 */
export class EncryptionKeyHelper<
  T extends EncryptAlgorithm = EncryptAlgorithm,
> {
  /**
   * @param algorithm Encryption algorithm to use for this instance.
   */
  constructor(public algorithm: T) {}

  //
  // OVERLOADS
  //

  /**
   * @param length Length in bits of the key to generate. Defaults to 256.
   * @returns `CryptoKey` ready to encrypt and decrypt.
   */
  public async key(length?: number): Promise<CryptoKey>;

  /**
   * @param key Key bytes (previously obtained with `export()`).
   * @returns `CryptoKey` ready to encrypt and decrypt.
   */
  public async key(key: BufferSource): Promise<CryptoKey>;

  //
  // Implementation
  //

  public async key(keyOrLength?: BufferSource | number): Promise<CryptoKey> {
    try {
      if (
        keyOrLength instanceof ArrayBuffer ||
        ArrayBuffer.isView(keyOrLength)
      ) {
        return await crypto.subtle.importKey(
          'raw',
          keyOrLength,
          { name: this.algorithm },
          true,
          ['encrypt', 'decrypt'],
        );
      }

      return await crypto.subtle.generateKey(
        { name: this.algorithm, length: keyOrLength || 256 },
        true,
        ['encrypt', 'decrypt'],
      );
    } catch (error) {
      throw new EncryptionKeyError(error);
    }
  }

  /**
   * Exports a key to raw bytes so it can be stored.
   *
   * @param options.key Key generated with `key()`.
   * @returns The key bytes, as an `ArrayBuffer`.
   */
  public async export({ key }: { key: CryptoKey }): Promise<ArrayBuffer> {
    try {
      return await crypto.subtle.exportKey('raw', key);
    } catch (error) {
      throw new EncryptionKeyError(error);
    }
  }
}
