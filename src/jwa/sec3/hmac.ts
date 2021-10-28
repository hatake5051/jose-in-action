// --------------------BEGIN JWA HMAC algorithms --------------------
import { JWK } from '../../jwk';
import { JWSSignature, MACOperator } from '../../jws';
import { BASE64URL_DECODE } from '../../util';

export { HSAlg, isHSAlg, HMACOperator };

/**
 * HMAC アルゴリズムで MAC の生成と検証を行うオペレータを定義する
 */
const HMACOperator: MACOperator<HSAlg> = { mac, verify };

/**
 * RFC7518#3.2.  HMAC with SHA-2 Functions のアルゴリズム識別子を列挙する。
 */
type HSAlg = typeof hsAlgList[number];

/**
 * 引数が HMAC アルゴリズム識別子か確認する。
 */
const isHSAlg = (arg: unknown): arg is HSAlg => {
  if (typeof arg !== 'string') return false;
  return hsAlgList.some((a) => a === arg);
};

const hsAlgList = ['HS256', 'HS384', 'HS512'] as const;

/**
 * HMAC アルゴリズムに従い MAC を計算する。
 * 計算を行う前に、鍵長が十分かどうか判定を行う。
 */
async function mac(alg: HSAlg, key: JWK<'oct'>, m: Uint8Array): Promise<JWSSignature> {
  // ハッシュの出力サイズ以上の鍵長が必要である (RFC8517#3.2)
  if (BASE64URL_DECODE(key.k).length < parseInt(alg.slice(2)) / 8) {
    throw new EvalError(`${alg} では鍵長が ${parseInt(alg.slice(2)) / 8} 以上にしてください`);
  }

  const { k: keyAlg, s: sigAlg } = params(alg);
  const k = await window.crypto.subtle.importKey('jwk', key as JsonWebKey, keyAlg, false, ['sign']);
  const s = await window.crypto.subtle.sign(sigAlg, k, m);
  return new Uint8Array(s);
}

/**
 * HMAC アルゴリズムに従い、与えられた MAC を検証する。
 */
async function verify(
  alg: HSAlg,
  key: JWK<'oct'>,
  m: Uint8Array,
  s: JWSSignature
): Promise<boolean> {
  // ハッシュの出力サイズ以上の鍵長が必要である (RFC8517#3.2)
  if (BASE64URL_DECODE(key.k).length < parseInt(alg.slice(2)) / 8) {
    throw new EvalError(`${alg} では鍵長が ${parseInt(alg.slice(2)) / 8} 以上にしてください`);
  }

  const { k: keyAlg, s: sigAlg } = params(alg);

  const k = await window.crypto.subtle.importKey('jwk', key as JsonWebKey, keyAlg, false, [
    'verify',
  ]);
  const isValid = await window.crypto.subtle.verify(sigAlg, k, s, m);
  return isValid;
}

function params(alg: HSAlg): { k: HmacImportParams; s: AlgorithmIdentifier } {
  const name = 'HMAC';
  const keyAlg: HmacImportParams = { name, hash: 'SHA-' + alg.slice(2) };
  const sigAlg: AlgorithmIdentifier = name;
  return { k: keyAlg, s: sigAlg };
}

// --------------------END JWA HMAC algorithms --------------------
