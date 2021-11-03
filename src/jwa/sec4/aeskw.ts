import { KeyWrapper } from 'jwe/ineterface';
import { JWECEK, JWEEncryptedKey } from 'jwe/type';
import { JWK } from 'jwk';

export { AKWAlg, isAKWAlg, AKWKeyWrapper };

const AKWKeyWrapper: KeyWrapper<AKWAlg> = { wrap, unwrap };

/**
 * RFC7518#4.4.  Key Wrapping with AES Key Wrap のアルゴリズムを列挙する。
 */
type AKWAlg = typeof akwAlgList[number];
const isAKWAlg = (arg: unknown): arg is AKWAlg =>
  typeof arg === 'string' && akwAlgList.some((a) => a === arg);
const akwAlgList = ['A128KW', 'A192KW', 'A256KW'] as const;

/**
 * AES Key Wrapping アルゴリズムに従い、 Content Encryption Key をラッピングして暗号化する。
 */
async function wrap(key: JWK<'oct'>, cek: JWECEK): Promise<JWEEncryptedKey> {
  // Crypto API の wrapKey を使って CEK をラッピングするが、
  // wrapKey の引数には Crypt API の CryptoKey 形式にして、 CEK を渡す必要がある。
  // また、 CryptoKey をインポートする際は鍵の仕様用途などを指定する必要がある。
  // しかし指定した情報はラッピングに同梱されないため、適当に AES-GCM の鍵として CEK をインポートしている。
  const apiCEK = await window.crypto.subtle.importKey('raw', cek, 'AES-GCM', true, ['encrypt']);
  const k = await window.crypto.subtle.importKey('jwk', key, { name: 'AES-KW' }, false, [
    'wrapKey',
  ]);
  const e = await window.crypto.subtle.wrapKey('raw', apiCEK, k, { name: 'AES-KW' });
  return new Uint8Array(e);
}

/**
 * AES Key Wrapping アルゴリズムに従い、 JWE Encrypted Key を案ラップして CEK を復号する。
 */
async function unwrap(key: JWK<'oct'>, ek: JWEEncryptedKey): Promise<JWECEK> {
  const k = await window.crypto.subtle.importKey('jwk', key, { name: 'AES-KW' }, false, [
    'unwrapKey',
  ]);
  const e = await window.crypto.subtle.unwrapKey(
    'raw',
    ek,
    k,
    { name: 'AES-KW' },
    'AES-GCM',
    true,
    ['decrypt']
  );
  return new Uint8Array(await window.crypto.subtle.exportKey('raw', e));
}
