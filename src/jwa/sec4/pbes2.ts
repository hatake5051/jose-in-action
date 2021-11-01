import { JWECEK, JWEEncryptedKey } from 'jwe';
import { KeyWrapper } from 'jwe/internal/keymgmt';
import { JWK } from 'jwk';
import { BASE64URL, BASE64URL_DECODE, CONCAT, UTF8 } from 'utility';
import { AKWKeyWrapper } from './aeskw';

export { PBES2Alg, isPBES2Alg, JWEPBES2HeaderParams, PBES2KeyWrapper };

const PBES2KeyWrapper: KeyWrapper<PBES2Alg> = { wrap, unwrap };

/**
 * RFC7518#4.8.  Key Encryption with PBES2
 */
type PBES2Alg = typeof pbes2AlgList[number];
const isPBES2Alg = (arg: unknown): arg is PBES2Alg =>
  typeof arg === 'string' && pbes2AlgList.some((a) => a === arg);
const pbes2AlgList = ['PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'] as const;

/**
 * RFC7518#4.8.1 PBES2 Key Encryption 用のヘッダーパラメータ
 */
type JWEPBES2HeaderParams = {
  alg: PBES2Alg;
  /**
   * RFC7518#4.8.1.2 PBES2 Count Header Parameter は PBKDF2 iteration count を表現する。
   * 最小反復回数は 1000 が推奨されている (RFC2898)
   */
  p2c: number;
  /**
   * RFC7518#4.8.1.1 PBES2 Salt Input Header Parameter は PBKDF2 salt input を BASE64URL エンコードしている。
   * 使用される salt value は UTF8(Alg) || 0x00 || Salt Input である。
   */
  p2s: string;
};

/**
 * RFC2898#6.2.1 に基づいて、ユーザが指定したパスワードで CEK をラップする。
 * パスワードは JWK<oct> で表現されているが、k にはパスワードの UTF-8 表現を BASE64URL エンコードしたものが入る。
 */
async function wrap(
  key: JWK<'oct'>,
  cek: JWECEK,
  h?: JWEPBES2HeaderParams
): Promise<JWEEncryptedKey> {
  if (!h) throw new TypeError('PBES2Alg にはヘッダーにあるパラメータが必須');
  const { HASH_ALG, KEY_LEN } = algParams(h.alg);
  /**
   * P はパスワードの UTF-8 表現である。
   */
  const P = BASE64URL_DECODE(key.k);
  /**
   * RFC2898#6.1.1 Step1 salt(S) と iteration count(c) を決める
   * RFC7518#4.8.1.1 では salt を (UTF8(Alg) || 0x00 || Header.p2s) として定めている。
   * RFC7518#4.8.1.2 では iteration count を Header.p2c として定めている。
   */
  const S = CONCAT(CONCAT(UTF8(h.alg), new Uint8Array([0])), BASE64URL_DECODE(h.p2s));
  const c = h.p2c;
  /**
   * RFC2898#6.1.1 Step2 導出される鍵のオクテット長を決める。
   * RFC7518#4.8.1 では AES KW でラップするとしているので、 Header.alg アルゴリズムに応じて鍵長が決まる。
   */
  const dkLen = KEY_LEN;
  /**
   * RFC2898#6.1.1 Step3  KDF を適用する。 PBKDF2 で使用するハッシュ関数は Header.alg に応じて決まる。
   */
  const DK = await PBKDF2(P, S, c, dkLen, HASH_ALG);
  /**
   * RFC2898#6.1.1 Step4 cek を暗号化する。
   * RFC7518 では AES KW を使うとしているので AKWKeyWrapper 実装を用いている。
   */
  return AKWKeyWrapper.wrap({ kty: 'oct', k: BASE64URL(DK) }, cek);
}

/**
 * RFC2898#6.2.2 に基づいて、ユーザが指定したパスワードで EK を復号する。
 * パスワードは JWK<oct> で表現されているが、k にはパスワードの UTF-8 表現を BASE64URL エンコードしたものが入る。
 */
async function unwrap(
  key: JWK<'oct'>,
  ek: JWEEncryptedKey,
  h?: JWEPBES2HeaderParams
): Promise<JWECEK> {
  if (!h) throw TypeError('PBES2Alg にはヘッダーにあるパラメータが必須');
  const { HASH_ALG, KEY_LEN } = algParams(h.alg);
  const P = BASE64URL_DECODE(key.k);
  // Step1
  const S = CONCAT(CONCAT(UTF8(h.alg), new Uint8Array([0])), BASE64URL_DECODE(h.p2s));
  // Step2
  const c = h.p2c;
  // Step3
  const dkLen = KEY_LEN;
  // Step4
  const DK = await PBKDF2(P, S, c, dkLen, HASH_ALG);
  // Step5
  return AKWKeyWrapper.unwrap({ kty: 'oct', k: BASE64URL(DK) }, ek);
}

function algParams(alg: PBES2Alg) {
  switch (alg) {
    case 'PBES2-HS256+A128KW':
      return { HASH_ALG: 'SHA-256', KEY_LEN: 128 };
    case 'PBES2-HS384+A192KW':
      return { HASH_ALG: 'SHA-384', KEY_LEN: 192 };
    case 'PBES2-HS512+A256KW':
      return { HASH_ALG: 'SHA-512', KEY_LEN: 256 };
  }
}

/**
 * RFC2898#5.2 PBKDF2 を実装する。実体は CryptoAPI.deriveBits で行っている。
 */
async function PBKDF2(
  P: Uint8Array,
  S: Uint8Array,
  c: number,
  dkLen: number,
  hash: string
): Promise<Uint8Array> {
  const cP = await window.crypto.subtle.importKey('raw', P, 'PBKDF2', false, ['deriveBits']);
  const DK = await window.crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash, salt: S, iterations: c },
    cP,
    dkLen
  );
  return new Uint8Array(DK);
}
