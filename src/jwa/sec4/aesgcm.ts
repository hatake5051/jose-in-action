import { KeyWrapper } from 'jwe/ineterface';
import { JWECEK, JWEEncryptedKey, JWETag } from 'jwe/type';
import { JWK } from 'jwk';
import { BASE64URL, BASE64URL_DECODE, CONCAT, isObject } from 'utility';

export {
  AGCMKWAlg,
  isAGCMKWAlg,
  AGCMKWHeaderParams,
  AGCMKWHeaderParamNames,
  isPartialAGCMKWHeaderParams,
  isAGCMKWHeaderParams,
  equalsAGCMKWHeaderParams,
  AGCMKeyWrapper,
};

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
 * RFC7518#4.7.  Key Encryption with AES GCM のアルゴリズムを列挙する
 */
type AGCMKWAlg = typeof agcmAlgList[number];
const isAGCMKWAlg = (arg: unknown): arg is AGCMKWAlg =>
  typeof arg === 'string' && agcmAlgList.some((a) => a === arg);
const agcmAlgList = ['A128GCMKW', 'A192GCMKW', 'A256GCMKW'] as const;

/**
 * RFC7518#4.7.1 AES GCM Key Encryption で使用されるヘッダーパラメータ
 */
type AGCMKWHeaderParams = {
  /**
   * Initialization Vector Parameter はキー暗号化に使用される 96 bit の iv を base64url-encode した文字列
   */
  iv: string;
  /**
   * Authentication Tag Parameter はキー暗号化の結果の認証タグを base64url-encode した文字列
   */
  tag: string;
};

const AGCMKWHeaderParamNames = ['iv', 'tag'] as const;

const isPartialAGCMKWHeaderParams = (arg: unknown): arg is Partial<AGCMKWHeaderParams> =>
  isObject<Partial<AGCMKWHeaderParams>>(arg) &&
  AGCMKWHeaderParamNames.every((n) => !arg[n] || typeof arg[n] === 'string');

const isAGCMKWHeaderParams = (arg: unknown): arg is AGCMKWHeaderParams =>
  isPartialAGCMKWHeaderParams(arg) && arg.iv != null && arg.tag != null;

function equalsAGCMKWHeaderParams(
  l?: Partial<AGCMKWHeaderParams>,
  r?: Partial<AGCMKWHeaderParams>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return l.iv === r.iv && l.tag === r.tag;
}

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
