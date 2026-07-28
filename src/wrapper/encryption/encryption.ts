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
 * Utilidad para generar keys, encriptar y desencriptar datos usando
 * los distintos modos de AES soportados por SubtleCrypto.
 * Soporta AES-GCM, AES-CBC y AES-CTR con type-safe overloading.
 *
 * @example
 * const enc = new Encryption('AES-GCM');
 * const key = await enc.key();
 * const { ciphertext, iv } = await enc.encrypt('mi texto secreto', key);
 * const texto = await enc.decrypt(ciphertext, key, iv);
 */
export class Encryption<
  T extends EncryptAlgorithm = EncryptAlgorithm,
> extends EncryptionKeyHelper<T> {
  //
  // OVERLOADS ENCRYPT
  //

  /**
   * Encripta un texto con la key indicada (Para GCM y CBC).
   *
   * @param buffer Texto a encriptar.
   * @param key Key generada con `key()`.
   * @param iv Vector de inicializacion. Si no se proporciona, se genera uno aleatorio.
   * @returns Objeto con el `ciphertext` en Base64 y el `iv` en Base64 usado.
   */
  public async encrypt<U extends 'AES-GCM' | 'AES-CBC'>(
    this: Encryption<U>,
    buffer: string,
    key: CryptoKey,
    iv?: Uint8Array,
  ): Promise<{ ciphertext: string; iv: string }>;

  /**
   * Encripta un texto con la key indicada (Para CTR).
   *
   * @param buffer Texto a encriptar.
   * @param key Key generada con `key()`.
   * @param iv Vector de inicializacion (usado como counter). Si no se proporciona, se genera uno.
   * @param length Longitud del contador en bits. Requerido para AES-CTR.
   * @returns Objeto con el `ciphertext` en Base64 y el `iv` en Base64 usado.
   */
  public async encrypt<U extends 'AES-CTR'>(
    this: Encryption<U>,
    buffer: string,
    key: CryptoKey,
    iv?: Uint8Array,
    length?: number,
  ): Promise<{ ciphertext: string; iv: string }>;

  //
  // IMPLEMENTACION ENCRYPT
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
  // OVERLOADS DECRYPT
  //

  /**
   * Desencripta un ciphertext con la key y el iv usados al encriptar (Para GCM y CBC).
   *
   * @param ciphertext Dato encriptado en Base64, obtenido de `encrypt()`.
   * @param key Misma key usada en `encrypt()`.
   * @param iv Mismo iv en Base64 devuelto por `encrypt()`.
   * @returns El texto original desencriptado.
   */
  public async decrypt<U extends 'AES-GCM' | 'AES-CBC'>(
    this: Encryption<U>,
    ciphertext: string,
    key: CryptoKey,
    iv: string,
  ): Promise<string>;

  /**
   * Desencripta un ciphertext con la key y el iv usados al encriptar (Para CTR).
   *
   * @param ciphertext Dato encriptado en Base64, obtenido de `encrypt()`.
   * @param key Misma key usada en `encrypt()`.
   * @param iv Mismo iv en Base64 devuelto por `encrypt()` (usado como counter).
   * @param length Longitud del contador en bits. Por defecto 64.
   * @returns El texto original desencriptado.
   */
  public async decrypt<U extends 'AES-CTR'>(
    this: Encryption<U>,
    ciphertext: string,
    key: CryptoKey,
    iv: string,
    length?: number,
  ): Promise<string>;

  //
  // IMPLEMENTACION DECRYPT
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
   * Genera un Vector de Inicializacion (IV) aleatorio del tamaño correcto
   * segun el algoritmo configurado (12 bytes para GCM, 16 para CBC/CTR).
   *
   * @returns Nuevo IV generado.
   */
  public generateIV(): Uint8Array {
    return crypto.getRandomValues(
      new Uint8Array(this.algorithm === 'AES-GCM' ? 12 : 16),
    );
  }
}
