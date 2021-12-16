// --------------------BEGIN JWA HMAC algorithms --------------------

import { JWK } from 'jwk';
import { MACOperator } from 'jws/interface';
import { JWSSignature } from 'jws/type';
import { BASE64URL_DECODE } from 'utility';
import { HSAlg } from './alg';

export { HMACOperator };

/**
 * HMAC アルゴリズムで MAC の生成と検証を行うオペレータを定義する
 */
const HMACOperator: MACOperator<HSAlg> = { mac, verify };

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
  return new Uint8Array(s) as JWSSignature;
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
