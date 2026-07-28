export class CryptoEdgeError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'CryptoEdgeError';
  }
}

export class HashError extends CryptoEdgeError {
  constructor(cause: unknown) {
    super('Hash generation failed', { cause });
    this.name = 'HashError';
  }
}

export class SignatureSignError extends CryptoEdgeError {
  constructor(cause: unknown) {
    super('Signature sign failed', { cause });
    this.name = 'SignatureSignError';
  }
}

export class SignatureVerifyError extends CryptoEdgeError {
  constructor(cause: unknown) {
    super('Signature verification failed', { cause });
    this.name = 'SignatureVerifyError';
  }
}

export class EncryptionEncryptError extends CryptoEdgeError {
  constructor(cause: unknown) {
    super('Encryption failed', { cause });
    this.name = 'EncryptionEncryptError';
  }
}

export class EncryptionDecryptError extends CryptoEdgeError {
  constructor(cause: unknown) {
    super('Decryption failed', { cause });
    this.name = 'EncryptionDecryptError';
  }
}

export class SignatureKeyError extends CryptoEdgeError {
  constructor(cause: unknown) {
    super('Failed to generate signature key', { cause });
    this.name = 'SignatureKeyError';
  }
}

export class EncryptionKeyError extends CryptoEdgeError {
  constructor(cause: unknown) {
    super('Encryption key operation failed', { cause });
    this.name = 'EncryptionKeyError';
  }
}
