export type EncryptAlgorithm = 'AES-GCM' | 'AES-CBC' | 'AES-CTR';

/**
 * Clase para gestionar claves criptograficas simetricas para encriptacion.
 * Soporta generar nuevas claves aleatorias o importarlas desde bytes crudos.
 *
 * @example
 * const enc = new EncryptionKeyHelper('AES-GCM');
 * const key = await enc.key(); // Genera una key de 256 bits
 * const bytes = await enc.export({ key });
 * const importedKey = await enc.key(bytes); // Importa la key
 */
export class EncryptionKeyHelper<
  T extends EncryptAlgorithm = EncryptAlgorithm,
> {
  /**
   * @param algorithm Algoritmo de encriptacion para usar en esta instancia.
   */
  constructor(public algorithm: T) {}

  //
  // OVERLOADS
  //

  /**
   * @param length Longitud en bits de la clave a generar. Por defecto 256.
   * @returns `CryptoKey` lista para encriptar y desencriptar.
   */
  public async key(length?: number): Promise<CryptoKey>;

  /**
   * @param key Bytes de la clave (obtenidos previamente con `export()`).
   * @returns `CryptoKey` lista para encriptar y desencriptar.
   */
  public async key(key: BufferSource): Promise<CryptoKey>;

  //
  // Implementacion
  //

  public async key(keyOrLength?: BufferSource | number): Promise<CryptoKey> {
    if (keyOrLength instanceof ArrayBuffer || ArrayBuffer.isView(keyOrLength)) {
      return crypto.subtle.importKey(
        'raw',
        keyOrLength,
        { name: this.algorithm },
        true,
        ['encrypt', 'decrypt'],
      );
    }

    return crypto.subtle.generateKey(
      { name: this.algorithm, length: keyOrLength || 256 },
      true,
      ['encrypt', 'decrypt'],
    );
  }

  /**
   * Exporta una clave a bytes crudos para poder guardarla.
   *
   * @param options.key Clave generada con `key()`.
   * @returns Los bytes de la clave, como `ArrayBuffer`.
   */
  public async export({ key }: { key: CryptoKey }): Promise<ArrayBuffer> {
    return await crypto.subtle.exportKey('raw', key);
  }
}
