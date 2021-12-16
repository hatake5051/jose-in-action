import { KeyWrapper } from 'jwe/ineterface';
import { JWECEK, JWEEncryptedKey, JWETag } from 'jwe/type';
import { JWK } from 'jwk';
import { BASE64URL, BASE64URL_DECODE, CONCAT } from 'utility';
import { AGCMKWAlg } from './alg';
import { AGCMKWHeaderParams, isAGCMKWHeaderParams } from './header';

export { AGCMKeyWrapper };

const AGCMKeyWrapper: KeyWrapper<AGCMKWAlg> = {
  wrap: async (key: JWK<'oct'>, cek: JWECEK, h?: Partial<AGCMKWHeaderParams>) => {
    return wrap(key, cek, h);
  },
  unwrap: async (key: JWK<'oct'>, ek: JWEEncryptedKey, h?: Partial<AGCMKWHeaderParams>) => {
    if (!isAGCMKWHeaderParams(h)) {
      throw new TypeError(`JOSE Header for AES-GCM Key Wrapping に必須パラメータがない(iv, tag)`);
    }
    return unwrap(key, ek, h);
  },
};

/**
 * AES GCM アルゴリズムを使って CEK を暗号化する。
 */
async function wrap(
  key: JWK<'oct'>,
  cek: JWECEK,
  h?: Partial<AGCMKWHeaderParams>
): Promise<{ ek: JWEEncryptedKey; h: AGCMKWHeaderParams }> {
  const iv = h?.iv ? BASE64URL_DECODE(h.iv) : window.crypto.getRandomValues(new Uint8Array(12));
  // IV は 96bit である必要がある (REQUIRED)
  if (iv.length * 8 !== 96) {
    throw new TypeError('IV は 96bit である必要がある。');
  }
  // WecCryptoAPI を使うと JWK.alg チェックでエラーが出てしまう c.f.) https://w3c.github.io/webcrypto/#aes-gcm-operations
  // WebCryptoAPI は JWE.alg に対応できていないのかな...
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { alg, ...keyWithoutAlg } = key;
  const k = await window.crypto.subtle.importKey('jwk', keyWithoutAlg, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);
  const e = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, cek));
  const ek = e.slice(0, e.length - 16) as JWEEncryptedKey;
  // tag は Header に格納される。
  const tag = e.slice(e.length - 16) as JWETag;
  return { ek, h: { iv: h?.iv ?? BASE64URL(iv), tag: BASE64URL(tag) } };
}

/**
 * AES GCM アルゴリズムを使って Encrypted Key を復号する。
 */
async function unwrap(
  key: JWK<'oct'>,
  ek: JWEEncryptedKey,
  h: AGCMKWHeaderParams
): Promise<JWECEK> {
  const iv = BASE64URL_DECODE(h.iv);
  // IV は 96bit である必要がある (REQUIRED)
  if (iv.length * 8 !== 96) {
    throw new TypeError('IV は 96bit である必要がある。');
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { alg, ...keyWithoutAlg } = key;
  const k = await window.crypto.subtle.importKey('jwk', keyWithoutAlg, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);
  const e = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    k,
    CONCAT(ek, BASE64URL_DECODE(h.tag))
  );
  return new Uint8Array(e) as JWECEK;
}
