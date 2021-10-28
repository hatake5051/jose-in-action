// --------------------BEGIN JWA EC algorithms --------------------
import { JWACrv } from 'jwa/sec6/kty';
import { JWK } from 'jwk';
import { JWSSignature, SigOperator } from 'jws';

export { ECAlg, isECAlg, ECSigOperator };

/**
 * ECDSA アルゴリズムで署名の作成と検証を行うオペレータを定義する
 */
const ECSigOperator: SigOperator<ECAlg> = { sign, verify };

/**
 * RFC7518#3.4.  Digital Signature with ECDSA のアルゴリズム識別子を列挙する
 */
type ECAlg = typeof ecAlgList[number];

/**
 * 引数が ECDSA アルゴリズム識別子か確認する。
 */
const isECAlg = (arg: unknown): arg is ECAlg =>
  typeof arg === 'string' && ecAlgList.some((a) => a === arg);

const ecAlgList = ['ES256', 'ES384', 'ES512'] as const;

/**
 * ECDSA (alg)に従い、与えられたメッセージ(m)と秘密鍵(key) から署名を作成する。
 */
async function sign(alg: ECAlg, key: JWK<'EC', 'Priv'>, m: Uint8Array): Promise<JWSSignature> {
  const { keyAlg, sigAlg } = params(alg, key.crv);
  const k = await window.crypto.subtle.importKey('jwk', key as JsonWebKey, keyAlg, false, ['sign']);
  const s = await window.crypto.subtle.sign(sigAlg, k, m);
  return new Uint8Array(s);
}

/**
 * ECDSA (alg)に従い、与えられたメッセージ(m)と公開鍵(key) を署名(s)で検証する。
 */
async function verify(
  alg: ECAlg,
  key: JWK<'EC', 'Pub'>,
  m: Uint8Array,
  s: JWSSignature
): Promise<boolean> {
  const { keyAlg, sigAlg } = params(alg, key.crv);
  const k = await window.crypto.subtle.importKey('jwk', key as JsonWebKey, keyAlg, false, [
    'verify',
  ]);
  const sig = await window.crypto.subtle.verify(sigAlg, k, s, m);
  return sig;
}

function params(alg: ECAlg, crv: JWACrv): { keyAlg: EcKeyImportParams; sigAlg: EcdsaParams } {
  return {
    keyAlg: { name: 'ECDSA', namedCurve: crv },
    sigAlg: { name: 'ECDSA', hash: 'SHA-' + alg.slice(2) },
  };
}

// --------------------END JWA EC algorithms --------------------
