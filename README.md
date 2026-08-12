# crypto-edge

A wrapper library built on top of the Web Crypto API to abstract simple functionality like hashing, encryption and signing, with type-safe overloading and robust error handling. Designed for Edge environments and the browser.

[![Socket Badge](https://badge.socket.dev/npm/package/crypto-edge)](https://badge.socket.dev/npm/package/crypto-edge)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/baa4ts/crypto-edge)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=flat&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Rslib](https://img.shields.io/badge/Rslib-07C160?style=flat&logo=rsbuild&logoColor=white)](https://rslib.rs/)
[![Rstest](https://img.shields.io/badge/Rstest-00A8FF?style=flat&logo=rspack&logoColor=white)](https://rstest.rs/)

- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [Documentation - DeepWiki](https://deepwiki.com/baa4ts/crypto-edge)
- [Getting Started - DeepWiki](https://deepwiki.com/baa4ts/crypto-edge/1.1-getting-started)

## Features

- ✅ **Zero dependencies**: Uses the native browser/runtime API.
- ✅ **Type-safe overloading**: Smart autocomplete based on the algorithm (e.g. `salt` only appears for RSA-PSS, `length` only for AES-CTR).
- ✅ **Key management**: Generate, import and export keys easily.
- ✅ **Robust error handling**: Custom errors with a hierarchy that preserves the original cause (`cause`).
- ✅ **Edge-ready**: Ready for Cloudflare Workers, Vercel Edge Functions and browsers.

### Status

| Implementation | Status |
| :--- | :---: |
|   Hashing | ✓ |
|  Signing | ✓ |
| Encryption | ✓ |
| Custom Errors | ✓ |

## Installation

```bash
npm install crypto-edge
# or
pnpm add crypto-edge
# or
yarn add crypto-edge
```

## Basic usage

### Hash

```typescript
import { Hash } from 'crypto-edge';

const hash = await Hash('Hello world', 'SHA-256');
console.log(hash); // hexadecimal
```

### Symmetric encryption (AES)

```typescript
import { Encryption } from 'crypto-edge';

const enc = new Encryption('AES-GCM');
const key = await enc.key(); // generates a 256-bit key

const { ciphertext, iv } = await enc.encrypt('my secret text', key);
const text = await enc.decrypt(ciphertext, key, iv);

console.log(text); // 'my secret text'
```

### Digital signatures

```typescript
import { Signature } from 'crypto-edge';

const sig = new Signature('ECDSA');
const keyPair = await sig.key(); // generates a key pair

const signature = await sig.sign('message', keyPair);
const isValid = await sig.verify('message', signature, keyPair);

console.log(isValid); // true
```

## Error handling

The library provides a hierarchy of custom errors that extend `CryptoEdgeError`. Every error preserves the original cause using JavaScript's standard `cause` property.

```typescript
import { Encryption, EncryptionDecryptError, CryptoEdgeError } from 'crypto-edge';

const enc = new Encryption('AES-GCM');
const key = await enc.key();

try {
  // Attempt to decrypt invalid data or use the wrong key
  await enc.decrypt('corrupted-data', key, 'invalid-iv');
} catch (err) {
  if (err instanceof EncryptionDecryptError) {
    console.error('Decryption failed:', err.message);
    console.error('Original cause:', err.cause); // Native browser error
  }
}
```

### Error hierarchy

- **`CryptoEdgeError`**: Base class for all errors in the library.
  - **`HashError`**: Thrown when hash generation fails.
  - **Encryption errors**:
    - **`EncryptionEncryptError`**: Thrown when the encryption process fails.
    - **`EncryptionDecryptError`**: Thrown when the decryption process fails (e.g. tampered data, wrong key).
    - **`EncryptionKeyError`**: Thrown when generating, importing or exporting an encryption key fails.
  - **Signature errors**:
    - **`SignatureSignError`**: Thrown when the signing process fails.
    - **`SignatureVerifyError`**: Thrown when an error occurs while verifying the signature (not to be confused with a verification that returns `false`).
    - **`SignatureKeyError`**: Thrown when generating a signature key fails.

## API

### Hash

`Hash(buffer: string, algorithm: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'): Promise<string>`

Generates the hash of the text and returns it in hexadecimal.

### Encryption

`new Encryption(algorithm: 'AES-GCM' | 'AES-CBC' | 'AES-CTR')`

- `key(length?: number): Promise<CryptoKey>` – generates a new key (256 bits by default).
- `key(key: BufferSource): Promise<CryptoKey>` – imports a key from raw bytes.
- `encrypt(buffer: string, key: CryptoKey, iv?: Uint8Array, length?: number): Promise<{ ciphertext: string; iv: string }>` – encrypts the text. If no IV is provided, a random one is generated. The `length` parameter is exclusive to `AES-CTR`.
- `decrypt(ciphertext: string, key: CryptoKey, iv: string, length?: number): Promise<string>` – decrypts the text. The `length` parameter is exclusive to `AES-CTR`.
- `export({ key }: { key: CryptoKey }): Promise<ArrayBuffer>` – exports the key to raw bytes.
- `generateIV(): Uint8Array` – generates a random Initialization Vector of the correct size (12 bytes for GCM, 16 for CBC/CTR).

### Signature

`new Signature(algorithm: 'HMAC' | 'ECDSA' | 'RSASSA-PKCS1-v1_5' | 'RSA-PSS')`

- `key(): Promise<CryptoKey | CryptoKeyPair>` – generates a key or key pair depending on the algorithm (HMAC returns `CryptoKey`, the rest return `CryptoKeyPair`).
- `sign(buffer: string, key: CryptoKey | CryptoKeyPair, hash?: HashAlgorithm, salt?: number): Promise<string>` – signs the text and returns the signature in Base64. `hash` applies to HMAC/ECDSA, `salt` applies to RSA-PSS.
- `verify(buffer: string, signature: string, key: CryptoKey | CryptoKeyPair, hash?: HashAlgorithm, salt?: number): Promise<boolean>` – verifies the signature. Returns `true` if valid, `false` if it doesn't match.

## Supported algorithms

| Category        | Algorithms                                      |
|-----------------|-------------------------------------------------|
| Hash            | SHA-1, SHA-256, SHA-384, SHA-512                |
| Encryption      | AES-GCM, AES-CBC, AES-CTR                       |
| Signatures      | HMAC, ECDSA (P-256), RSASSA-PKCS1-v1_5, RSA-PSS |