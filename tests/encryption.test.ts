import { expect, test, describe } from '@rstest/core';
import { Encryption } from '../src/index';

describe('Encryption Helper', () => {
  // Tests basicos: encriptar → desencriptar → verificar texto identico

  test('AES-GCM: Encriptar y desencriptar texto basico', async () => {
    const enc = new Encryption('AES-GCM');
    const key = await enc.key();
    const texto = 'hola mundo';

    const { ciphertext, iv } = await enc.encrypt(texto, key);
    const textoDesencriptado = await enc.decrypt(ciphertext, key, iv);

    expect(textoDesencriptado).toBe(texto);
  });

  test('AES-GCM: Encriptar y desencriptar texto largo (1000 caracteres)', async () => {
    const enc = new Encryption('AES-GCM');
    const key = await enc.key();
    const texto = 'a'.repeat(1000);

    const { ciphertext, iv } = await enc.encrypt(texto, key);
    const textoDesencriptado = await enc.decrypt(ciphertext, key, iv);

    expect(textoDesencriptado).toBe(texto);
    expect(textoDesencriptado.length).toBe(1000);
  });

  test('AES-GCM: Encriptar y desencriptar texto vacio', async () => {
    const enc = new Encryption('AES-GCM');
    const key = await enc.key();
    const texto = '';

    const { ciphertext, iv } = await enc.encrypt(texto, key);
    const textoDesencriptado = await enc.decrypt(ciphertext, key, iv);

    expect(textoDesencriptado).toBe(texto);
    expect(textoDesencriptado.length).toBe(0);
  });

  test('AES-GCM: Encriptar y desencriptar con caracteres especiales', async () => {
    const enc = new Encryption('AES-GCM');
    const key = await enc.key();
    const texto = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const { ciphertext, iv } = await enc.encrypt(texto, key);
    const textoDesencriptado = await enc.decrypt(ciphertext, key, iv);

    expect(textoDesencriptado).toBe(texto);
  });

  test('AES-GCM: Encriptar y desencriptar con unicode (chino, arabe, emoji)', async () => {
    const enc = new Encryption('AES-GCM');
    const key = await enc.key();
    const texto = '你好世界 مرحبا العالم 🔐🔒🗝️';

    const { ciphertext, iv } = await enc.encrypt(texto, key);
    const textoDesencriptado = await enc.decrypt(ciphertext, key, iv);

    expect(textoDesencriptado).toBe(texto);
  });

  test('AES-GCM: Encriptar y desencriptar con saltos de linea y tabs', async () => {
    const enc = new Encryption('AES-GCM');
    const key = await enc.key();
    const texto = 'linea1\nlinea2\tcon\ttabs\rcarriage\nreturn';

    const { ciphertext, iv } = await enc.encrypt(texto, key);
    const textoDesencriptado = await enc.decrypt(ciphertext, key, iv);

    expect(textoDesencriptado).toBe(texto);
  });

  // Tests CBC

  test('AES-CBC: Encriptar y desencriptar texto basico', async () => {
    const enc = new Encryption('AES-CBC');
    const key = await enc.key();
    const texto = 'mensaje secreto con cbc';

    const { ciphertext, iv } = await enc.encrypt(texto, key);
    const textoDesencriptado = await enc.decrypt(ciphertext, key, iv);

    expect(textoDesencriptado).toBe(texto);
  });

  test('AES-CBC: Encriptar y desencriptar con IV personalizado', async () => {
    const enc = new Encryption('AES-CBC');
    const key = await enc.key();
    const ivPersonalizado = enc.generateIV();
    const texto = 'texto con iv custom';

    const { ciphertext, iv } = await enc.encrypt(texto, key, ivPersonalizado);
    const textoDesencriptado = await enc.decrypt(ciphertext, key, iv);

    expect(textoDesencriptado).toBe(texto);
  });

  test('AES-CBC: Encriptar y desencriptar texto largo', async () => {
    const enc = new Encryption('AES-CBC');
    const key = await enc.key();
    const texto = 'b'.repeat(500);

    const { ciphertext, iv } = await enc.encrypt(texto, key);
    const textoDesencriptado = await enc.decrypt(ciphertext, key, iv);

    expect(textoDesencriptado).toBe(texto);
  });

  // Tests CTR

  test('AES-CTR: Encriptar y desencriptar texto basico', async () => {
    const ctr = new Encryption('AES-CTR');
    const key = await ctr.key();
    const texto = 'mensaje secreto con ctr';

    const { ciphertext, iv } = await ctr.encrypt(texto, key, undefined, 64);
    const textoDesencriptado = await ctr.decrypt(ciphertext, key, iv, 64);

    expect(textoDesencriptado).toBe(texto);
  });

  test('AES-CTR: Encriptar y desencriptar con length 32 bits', async () => {
    const ctr = new Encryption('AES-CTR');
    const key = await ctr.key();
    const texto = 'probando length 32';

    const { ciphertext, iv } = await ctr.encrypt(texto, key, undefined, 32);
    const textoDesencriptado = await ctr.decrypt(ciphertext, key, iv, 32);

    expect(textoDesencriptado).toBe(texto);
  });

  test('AES-CTR: Encriptar y desencriptar texto largo', async () => {
    const ctr = new Encryption('AES-CTR');
    const key = await ctr.key();
    const texto = 'c'.repeat(200);

    const { ciphertext, iv } = await ctr.encrypt(texto, key, undefined, 64);
    const textoDesencriptado = await ctr.decrypt(ciphertext, key, iv, 64);

    expect(textoDesencriptado).toBe(texto);
  });

  // Tests propiedades

  test('AES-GCM: Diferentes IVs generan diferentes ciphertexts', async () => {
    const enc = new Encryption('AES-GCM');
    const key = await enc.key();
    const texto = 'mismo texto diferente iv';

    const { ciphertext: cipher1, iv: iv1 } = await enc.encrypt(texto, key);
    const { ciphertext: cipher2, iv: iv2 } = await enc.encrypt(texto, key);

    expect(cipher1).not.toBe(cipher2);
    expect(iv1).not.toBe(iv2);

    const decipher1 = await enc.decrypt(cipher1, key, iv1);
    const decipher2 = await enc.decrypt(cipher2, key, iv2);

    expect(decipher1).toBe(texto);
    expect(decipher2).toBe(texto);
  });

  test('AES-GCM: Ciphertext alterado lanza excepcion', async () => {
    const enc = new Encryption('AES-GCM');
    const key = await enc.key();
    const texto = 'texto original';

    const { ciphertext, iv } = await enc.encrypt(texto, key);
    const ciphertextAlterado =
      ciphertext.substring(0, 10) + 'XXX' + ciphertext.substring(13);

    try {
      await enc.decrypt(ciphertextAlterado, key, iv);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeTruthy();
    }
  });

  test('IV generado tiene tamaño correcto para GCM (12 bytes)', async () => {
    const enc = new Encryption('AES-GCM');
    const iv = enc.generateIV();

    expect(iv.length).toBe(12);
  });

  test('IV generado tiene tamaño correcto para CBC (16 bytes)', async () => {
    const enc = new Encryption('AES-CBC');
    const iv = enc.generateIV();

    expect(iv.length).toBe(16);
  });

  test('IV generado tiene tamaño correcto para CTR (16 bytes)', async () => {
    const ctr = new Encryption('AES-CTR');
    const iv = ctr.generateIV();

    expect(iv.length).toBe(16);
  });

  test('Exportar e importar key permite desencriptar datos', async () => {
    const enc = new Encryption('AES-GCM');
    const keyOriginal = await enc.key();
    const texto = 'prueba export import';

    const { ciphertext, iv } = await enc.encrypt(texto, keyOriginal);

    const rawKey = await enc.export({ key: keyOriginal });
    const keyImportada = await enc.key(rawKey);

    const textoDesencriptado = await enc.decrypt(ciphertext, keyImportada, iv);

    expect(textoDesencriptado).toBe(texto);
  });

  test('Performance: Encriptar 50 mensajes en < 500ms', async () => {
    const enc = new Encryption('AES-GCM');
    const key = await enc.key();

    const start = performance.now();
    for (let i = 0; i < 50; i++) {
      await enc.encrypt(`mensaje-${i}`, key);
    }
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(500);
  });

  test('Performance: Desencriptar 50 mensajes en < 400ms', async () => {
    const enc = new Encryption('AES-GCM');
    const key = await enc.key();
    const { ciphertext, iv } = await enc.encrypt('test', key);

    const start = performance.now();
    for (let i = 0; i < 50; i++) {
      await enc.decrypt(ciphertext, key, iv);
    }
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(400);
  });
});
