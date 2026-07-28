import { expect, test } from '@rstest/core';
import { Hash, HashError, CryptoEdgeError } from '../src/index';

test('Hash SHA-1', async () => {
  expect(await Hash('hello', 'SHA-1')).toBe(
    'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
  );

  expect(await Hash('test', 'SHA-1')).toBe(
    'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3',
  );

  expect(await Hash('', 'SHA-1')).toBe(
    'da39a3ee5e6b4b0d3255bfef95601890afd80709',
  );
});

test('Hash SHA-256', async () => {
  expect(await Hash('hello', 'SHA-256')).toBe(
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
  );

  expect(await Hash('test', 'SHA-256')).toBe(
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  );

  expect(await Hash('', 'SHA-256')).toBe(
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
});

test('Hash SHA-384', async () => {
  expect(await Hash('hello', 'SHA-384')).toBe(
    '59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f',
  );

  expect(await Hash('test', 'SHA-384')).toBe(
    '768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9',
  );

  expect(await Hash('', 'SHA-384')).toBe(
    '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
  );
});

test('Hash SHA-512', async () => {
  expect(await Hash('hello', 'SHA-512')).toBe(
    '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043',
  );

  expect(await Hash('test', 'SHA-512')).toBe(
    'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff',
  );

  expect(await Hash('', 'SHA-512')).toBe(
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
  );
});

test('Algoritmo invalido lanza HashError', async () => {
  // @ts-expect-error - algoritmo invalido a proposito
  await expect(Hash('test', 'SHA-999')).rejects.toBeInstanceOf(HashError);
});

test('HashError es instancia de CryptoEdgeError', async () => {
  // @ts-expect-error - algoritmo invalido a proposito
  await expect(Hash('test', 'SHA-999')).rejects.toBeInstanceOf(CryptoEdgeError);
});

test('HashError preserva cause', async () => {
  try {
    // @ts-expect-error - algoritmo invalido a proposito
    await Hash('test', 'SHA-999');
  } catch (err) {
    expect(err).toBeInstanceOf(HashError);
    expect((err as HashError).cause).toBeDefined();
  }
});

test('Hash SHA-256 con texto largo', async () => {
  const texto = 'a'.repeat(10000);
  const result = await Hash(texto, 'SHA-256');
  expect(result).toHaveLength(64);
});

test('Hash SHA-256 con unicode y emojis', async () => {
  const result = await Hash('你好世界 🔐🔒🗝️', 'SHA-256');
  expect(result).toHaveLength(64);
});
