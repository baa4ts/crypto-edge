/**
 * Utility for converting between `ArrayBuffer` and Base64.
 * Used by `Signature` and `Encryption` to encode/decode data.
 */
export class Base64 {
  /**
   * Converts an `ArrayBuffer` to a Base64 string for storage or transmission.
   *
   * @param buffer Buffer to convert.
   * @returns String in Base64 format.
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
   * Converts a Base64 string to an `ArrayBuffer`.
   *
   * @param base64 String in Base64 format.
   * @returns Decoded `ArrayBuffer`.
   */
  public static base64ToBuffer(base64: string): ArrayBuffer {
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;
  }
}
