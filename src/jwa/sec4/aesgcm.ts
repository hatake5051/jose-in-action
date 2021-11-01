import { JWECEK, JWEEncryptedKey } from 'jwe';
import { KeyWrapper } from 'jwe/internal/keymgmt';
import { JWK } from 'jwk';
import { BASE64URL, BASE64URL_DECODE, CONCAT } from 'utility';

export { AGCMKWAlg, isAGCMKWAlg, JWEAGCMKWHeaderParams, AGCMKeyWrapper };

const AGCMKeyWrapper: KeyWrapper<AGCMKWAlg> = { wrap, unwrap };

/**
 * RFC7518#4.7.  Key Encryption with AES GCM のアルゴリズムを列挙する
 */
type AGCMKWAlg = typeof agcmAlgList[number];
const isAGCMKWAlg = (arg: unknown): arg is AGCMKWAlg =>
  typeof arg === 'string' && agcmAlgList.some((a) => a === arg);
const agcmAlgList = ['A128GCMKW', 'A192GCMKW', 'A256GCMKW'] as const;

/**
 * RFC7518#4.7.1 AES GCM Key Encryption で使用されるヘッダーパラメータ
 */
type JWEAGCMKWHeaderParams = {
  alg: AGCMKWAlg;
  /**
   * Initialization Vector Parameter はキー暗号化に使用される 96 bit の iv を base64url-encode した文字列
   */
  iv: string;
  /**
   * Authentication Tag Parameter はキー暗号化の結果の認証タグを base64url-encode した文字列
   */
  tag: string;
};

/**
 * AES GCM アルゴリズムを使って CEK を暗号化する。
 * h には認証タグ情報を書き加えるため mutable で渡してください。
 */
async function wrap(
  key: JWK<'oct'>,
  cek: JWECEK,
  h?: Pick<JWEAGCMKWHeaderParams, 'iv'> & Partial<Pick<JWEAGCMKWHeaderParams, 'tag'>>
): Promise<JWEEncryptedKey> {
  if (!h) throw new TypeError('Header Parameter が必須');
  const iv = BASE64URL_DECODE(h.iv);
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
  const ek: JWEEncryptedKey = e.slice(0, e.length - 16);
  // tag は Header に格納される。
  const tag = e.slice(e.length - 16);
  h.tag = BASE64URL(tag);
  return ek;
}

/**
 * AES GCM アルゴリズムを使って Encrypted Key を復号する。
 */
async function unwrap(
  key: JWK<'oct'>,
  ek: JWEEncryptedKey,
  h?: JWEAGCMKWHeaderParams
): Promise<JWECEK> {
  if (!h) throw new TypeError('Header Parameter が必須');
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
  return new Uint8Array(e);
}
