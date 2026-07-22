/**
 * Utilidad para convertir entre ArrayBuffer y Base64.
 * Usada por Signature y Encryption para codificar/decodificar datos.
 */
export class Base64 {
  /**
   * Convierte un ArrayBuffer a string Base64 para almacenamiento o transmision.
   *
   * @param buffer Buffer a convertir.
   * @returns String en formato Base64.
   */
  public static bufferToBase64(buffer: ArrayBufferLike): string {
    const byteArray = new Uint8Array(buffer);
    let binaryString = '';
    for (let i = 0; i < byteArray.length; i++) {
      binaryString += String.fromCharCode(byteArray[i]);
    }
    return btoa(binaryString);
  }

  /**
   * Convierte un string Base64 a ArrayBuffer.
   *
   * @param base64 String en formato Base64.
   * @returns ArrayBuffer descodificado.
   */
  public static base64ToBuffer(base64: string): ArrayBuffer {
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;
  }
}
