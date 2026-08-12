/**
 * Base error class for all errors thrown by this library. Every specific
 * error extends this class so consumers can catch `CryptoEdgeError` to
 * handle any failure from the package in one place.
 *
 * @example
 * try {
 *   await hash.sign(...);
 * } catch (err) {
 *   if (err instanceof CryptoEdgeError) {
 *     console.error(err.name, err.cause);
 *   }
 * }
 */
export class CryptoEdgeError extends Error {
  /**
   * @param message Human-readable error message.
   * @param options Standard `ErrorOptions`, typically used to pass the
   * original `cause`.
   */
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'CryptoEdgeError';
  }
}

/**
 * Thrown when hash generation fails, wrapping the underlying `SubtleCrypto` error.
 */
export class HashError extends CryptoEdgeError {
  /**
   * @param cause The original error thrown by `crypto.subtle.digest`.
   */
  constructor(cause: unknown) {
    super('Hash generation failed', { cause });
    this.name = 'HashError';
  }
}

/**
 * Thrown when signing data fails, wrapping the underlying `SubtleCrypto` error.
 */
export class SignatureSignError extends CryptoEdgeError {
  /**
   * @param cause The original error thrown by `crypto.subtle.sign`.
   */
  constructor(cause: unknown) {
    super('Signature sign failed', { cause });
    this.name = 'SignatureSignError';
  }
}

/**
 * Thrown when signature verification fails, wrapping the underlying
 * `SubtleCrypto` error.
 */
export class SignatureVerifyError extends CryptoEdgeError {
  /**
   * @param cause The original error thrown by `crypto.subtle.verify`.
   */
  constructor(cause: unknown) {
    super('Signature verification failed', { cause });
    this.name = 'SignatureVerifyError';
  }
}

/**
 * Thrown when encryption fails, wrapping the underlying `SubtleCrypto` error.
 */
export class EncryptionEncryptError extends CryptoEdgeError {
  /**
   * @param cause The original error thrown by `crypto.subtle.encrypt`.
   */
  constructor(cause: unknown) {
    super('Encryption failed', { cause });
    this.name = 'EncryptionEncryptError';
  }
}

/**
 * Thrown when decryption fails, wrapping the underlying `SubtleCrypto` error.
 */
export class EncryptionDecryptError extends CryptoEdgeError {
  /**
   * @param cause The original error thrown by `crypto.subtle.decrypt`.
   */
  constructor(cause: unknown) {
    super('Decryption failed', { cause });
    this.name = 'EncryptionDecryptError';
  }
}

/**
 * Thrown when generating a signature key fails, wrapping the underlying
 * `SubtleCrypto` error.
 */
export class SignatureKeyError extends CryptoEdgeError {
  /**
   * @param cause The original error thrown by `crypto.subtle.generateKey`.
   */
  constructor(cause: unknown) {
    super('Failed to generate signature key', { cause });
    this.name = 'SignatureKeyError';
  }
}

/**
 * Thrown when a key operation (generate/import/export) for encryption
 * fails, wrapping the underlying `SubtleCrypto` error.
 */
export class EncryptionKeyError extends CryptoEdgeError {
  /**
   * @param cause The original error thrown by the underlying key operation.
   */
  constructor(cause: unknown) {
    super('Encryption key operation failed', { cause });
    this.name = 'EncryptionKeyError';
  }
}
