# crypto-edge

Es una libreria wrapper construida sobre [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) para abstraer funcionalidades sencillas como hashing, criptografia y firmas, con tipado seguro y manejo de errores robusto. Diseñada para entornos Edge y el navegador.

[![Socket Badge](https://badge.socket.dev/npm/package/crypto-edge/1.0.0)](https://badge.socket.dev/npm/package/crypto-edge/1.0.0) [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/baa4ts/crypto-edge)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=flat&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Rslib](https://img.shields.io/badge/Rslib-07C160?style=flat&logo=rsbuild&logoColor=white)](https://rslib.rs/)
[![Rstest](https://img.shields.io/badge/Rstest-00A8FF?style=flat&logo=rspack&logoColor=white)](https://rstest.rs/)

- [Documentacion - DeepWiki](https://deepwiki.com/baa4ts/crypto-edge)
- [Primeros Pasos - DeepWiki](https://deepwiki.com/baa4ts/crypto-edge/1.1-getting-started)

## Características

- ✅ **Zero dependencies**: Usa la API nativa del navegador/Runtime.
- ✅ **Type-safe overloading**: Autocompletado inteligente según el algoritmo (ej. `salt` solo aparece en RSA-PSS, `length` solo en AES-CTR).
- ✅ **Key Management**: Genera, importa y exporta claves facilmente.
- ✅ **Manejo de errores robusto**: Errores personalizados con jerarquía que preservan la causa original (`cause`).
- ✅ **Edge-ready**: Lista para Cloudflare Workers, Vercel Edge Functions y navegadores.

### Status

| Implementacion | Estado |
| :--- | :---: |
|   Hashing | ✓ |
|  Signing | ✓ |
| Encryption | ✓ |
| Custom Errors | ✓ |

### Referencias
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)


## Instalacion

```bash
npm install crypto-edge
# o
pnpm add crypto-edge
# o
yarn add crypto-edge
```

## Uso basico

### Hash

```typescript
import { Hash } from 'crypto-edge';

const hash = await Hash('Hola mundo', 'SHA-256');
console.log(hash); // hexadecimal
```

### Cifrado simetrico (AES)

```typescript
import { Encryption } from 'crypto-edge';

const enc = new Encryption('AES-GCM');
const key = await enc.key(); // genera clave de 256 bits

const { ciphertext, iv } = await enc.encrypt('mi texto secreto', key);
const texto = await enc.decrypt(ciphertext, key, iv);

console.log(texto); // 'mi texto secreto'
```

### Firmas digitales

```typescript
import { Signature } from 'crypto-edge';

const sig = new Signature('ECDSA');
const keyPair = await sig.key(); // genera par de claves

const firma = await sig.sign('mensaje', keyPair);
const valida = await sig.verify('mensaje', firma, keyPair);

console.log(valida); // true
```

## Manejo de Errores

La librería proporciona una jerarquía de errores personalizados que se extienden de `CryptoEdgeError`. Todos los errores preservan la causa original usando la propiedad estándar `cause` de JavaScript.

```typescript
import { Encryption, EncryptionDecryptError, CryptoEdgeError } from 'crypto-edge';

const enc = new Encryption('AES-GCM');
const key = await enc.key();

try {
  // Intentar desencriptar datos invalidos o con clave incorrecta
  await enc.decrypt('datos-corruptos', key, 'iv-invalido');
} catch (err) {
  if (err instanceof EncryptionDecryptError) {
    console.error('La desencriptación falló:', err.message);
    console.error('Causa original:', err.cause); // Error nativo del navegador
  }
}
```

### Jerarquía de Errores

- **`CryptoEdgeError`**: Clase base para todos los errores de la librería.
  - **`HashError`**: Lanzado cuando falla la generación del hash.
  - **Errores de Encriptación**:
    - **`EncryptionEncryptError`**: Lanzado cuando falla el proceso de cifrado.
    - **`EncryptionDecryptError`**: Lanzado cuando falla el proceso de descifrado (ej. datos alterados, clave incorrecta).
    - **`EncryptionKeyError`**: Lanzado cuando falla la generación, importación o exportación de claves de cifrado.
  - **Errores de Firma**:
    - **`SignatureSignError`**: Lanzado cuando falla el proceso de firma.
    - **`SignatureVerifyError`**: Lanzado cuando hay un error al verificar la firma (no confundir con una verificación que devuelve `false`).
    - **`SignatureKeyError`**: Lanzado cuando falla la generación de claves de firma.

## API

### Hash

`Hash(buffer: string, algorithm: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'): Promise<string>`

Genera el hash del texto y lo devuelve en hexadecimal.

### Encryption

`new Encryption(algorithm: 'AES-GCM' | 'AES-CBC' | 'AES-CTR')`

- `key(length?: number): Promise<CryptoKey>` – genera una clave nueva (por defecto 256 bits).
- `key(key: BufferSource): Promise<CryptoKey>` – importa una clave desde bytes crudos.
- `encrypt(buffer: string, key: CryptoKey, iv?: Uint8Array, length?: number): Promise<{ ciphertext: string; iv: string }>` – cifra el texto. Si no se provee IV, se genera uno aleatorio. El parámetro `length` es exclusivo de `AES-CTR`.
- `decrypt(ciphertext: string, key: CryptoKey, iv: string, length?: number): Promise<string>` – descifra el texto. El parámetro `length` es exclusivo de `AES-CTR`.
- `export({ key }: { key: CryptoKey }): Promise<ArrayBuffer>` – exporta la clave a bytes crudos.
- `generateIV(): Uint8Array` – genera un Vector de Inicialización aleatorio del tamaño correcto (12 bytes para GCM, 16 para CBC/CTR).

### Signature

`new Signature(algorithm: 'HMAC' | 'ECDSA' | 'RSASSA-PKCS1-v1_5' | 'RSA-PSS')`

- `key(): Promise<CryptoKey | CryptoKeyPair>` – genera una clave o par de claves segun el algoritmo (HMAC devuelve `CryptoKey`, el resto `CryptoKeyPair`).
- `sign(buffer: string, key: CryptoKey | CryptoKeyPair, hash?: HashAlgorithm, salt?: number): Promise<string>` – firma el texto y devuelve la firma en Base64. `hash` aplica a HMAC/ECDSA, `salt` aplica a RSA-PSS.
- `verify(buffer: string, signature: string, key: CryptoKey | CryptoKeyPair, hash?: HashAlgorithm, salt?: number): Promise<boolean>` – verifica la firma. Devuelve `true` si es válida, `false` si no coincide.

## Algoritmos soportados

| Categoria       | Algoritmos                                      |
|-----------------|-------------------------------------------------|
| Hash            | SHA-1, SHA-256, SHA-384, SHA-512                |
| Cifrado         | AES-GCM, AES-CBC, AES-CTR                       |
| Firmas          | HMAC, ECDSA (P-256), RSASSA-PKCS1-v1_5, RSA-PSS |