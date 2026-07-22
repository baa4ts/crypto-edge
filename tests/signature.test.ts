import { expect, test, describe } from '@rstest/core';
import { Signature } from '../src/index';

describe('Signature Helper', () => {
  test('HMAC: Firmar y verificar correctamente un texto', async () => {
    const hmac = new Signature('HMAC');
    const key = await hmac.key();
    const texto = 'mensaje secreto hmac';

    const firmaBase64 = await hmac.sign(texto, key);
    expect(firmaBase64).toBeTruthy();
    expect(typeof firmaBase64).toBe('string');

    const esValido = await hmac.verify(texto, firmaBase64, key);
    expect(esValido).toBe(true);

    const esValidoFalso = await hmac.verify(
      'mensaje modificado',
      firmaBase64,
      key,
    );
    expect(esValidoFalso).toBe(false);
  });

  test('ECDSA: Firmar y verificar correctamente un texto', async () => {
    const ecdsa = new Signature('ECDSA');
    const keyPair = await ecdsa.key();
    const texto = 'mensaje secreto ecdsa';

    const firmaBase64 = await ecdsa.sign(texto, keyPair);
    expect(firmaBase64).toBeTruthy();

    expect(await ecdsa.verify(texto, firmaBase64, keyPair)).toBe(true);

    const firmaAlterada =
      firmaBase64.substring(0, 10) + 'XXXXXXXXXX' + firmaBase64.substring(20);
    expect(await ecdsa.verify(texto, firmaAlterada, keyPair)).toBe(false);
  });

  test('RSASSA-PKCS1-v1_5: Firmar y verificar correctamente un texto', async () => {
    const rsa = new Signature('RSASSA-PKCS1-v1_5');
    const keyPair = await rsa.key();
    const texto = 'mensaje secreto rsa pkcs';

    const firmaBase64 = await rsa.sign(texto, keyPair);

    expect(await rsa.verify(texto, firmaBase64, keyPair)).toBe(true);
    expect(await rsa.verify('texto incorrecto', firmaBase64, keyPair)).toBe(
      false,
    );
  });

  test('RSA-PSS: Firmar y verificar usando el parametro de salt', async () => {
    const rsaPss = new Signature('RSA-PSS');
    const keyPair = await rsaPss.key();
    const texto = 'mensaje secreto rsa pss';

    const firmaBase64 = await rsaPss.sign(texto, keyPair, 'SHA-256', 16);

    expect(
      await rsaPss.verify(texto, firmaBase64, keyPair, 'SHA-256', 16),
    ).toBe(true);
    expect(
      await rsaPss.verify(texto, firmaBase64, keyPair, 'SHA-256', 32),
    ).toBe(false);
  });

  test('ECDSA: Permitir cambiar el algoritmo de Hash (SHA-384)', async () => {
    const ecdsa = new Signature('ECDSA');
    const keyPair = await ecdsa.key();
    const texto = 'probando otro hash';

    const firmaBase64 = await ecdsa.sign(texto, keyPair, 'SHA-384');

    expect(await ecdsa.verify(texto, firmaBase64, keyPair, 'SHA-384')).toBe(
      true,
    );
    expect(await ecdsa.verify(texto, firmaBase64, keyPair, 'SHA-256')).toBe(
      false,
    );
  });

  test('ECDSA: Firmar pasando solo la privada suelta en vez del par completo', async () => {
    const ecdsa = new Signature('ECDSA');
    const parCompleto = await ecdsa.key();
    const texto = 'firmando con clave privada suelta';

    const soloLaPrivada = parCompleto.privateKey;

    const firmaBase64 = await ecdsa.sign(texto, soloLaPrivada);
    expect(firmaBase64).toBeTruthy();

    const esValidoConPar = await ecdsa.verify(texto, firmaBase64, parCompleto);
    expect(esValidoConPar).toBe(true);

    const soloLaPublica = parCompleto.publicKey;
    const esValidoConPublica = await ecdsa.verify(
      texto,
      firmaBase64,
      soloLaPublica,
    );
    expect(esValidoConPublica).toBe(true);
  });

  test('RSASSA-PKCS1-v1_5: Firmar pasando solo la privada suelta', async () => {
    const rsa = new Signature('RSASSA-PKCS1-v1_5');
    const parCompleto = await rsa.key();
    const texto = 'rsa con privada suelta';

    const soloLaPrivada = parCompleto.privateKey;
    const firmaBase64 = await rsa.sign(texto, soloLaPrivada);

    const soloLaPublica = parCompleto.publicKey;
    const esValido = await rsa.verify(texto, firmaBase64, soloLaPublica);
    expect(esValido).toBe(true);
  });

  test('HMAC: Firmas alternas de la misma data producen el mismo resultado', async () => {
    const hmac1 = new Signature('HMAC');
    const hmac2 = new Signature('HMAC');
    const key = await hmac1.key();

    const texto = 'data deterministica';

    // HMAC con misma key y mismo texto deberia dar misma firma
    const firma1 = await hmac1.sign(texto, key);
    const firma2 = await hmac2.sign(texto, key);

    // HMAC es determinista a diferencia de ECDSA/RSA
    expect(firma1).toBe(firma2);
  });

  test('Performance: Firmar 100 mensajes en < 500ms', async () => {
    const hmac = new Signature('HMAC');
    const key = await hmac.key();

    const start = performance.now();
    for (let i = 0; i < 100; i++) {
      await hmac.sign(`msg-${i}`, key);
    }
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(500);
  });

  test('Performance: Verificar 100 firmas en < 300ms', async () => {
    const hmac = new Signature('HMAC');
    const key = await hmac.key();
    const firma = await hmac.sign('test', key);

    const start = performance.now();
    for (let i = 0; i < 100; i++) {
      await hmac.verify('test', firma, key);
    }
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(300);
  });
});
