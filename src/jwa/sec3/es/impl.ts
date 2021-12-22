// --------------------BEGIN JWA EC algorithms --------------------

import { JWACrv } from 'jwa/sec6/ec/crv';
import { JWK } from 'jwk';
import { SigOperator } from 'jws/interface';
import { JWSSignature } from 'jws/type';
import { ESAlg } from './alg';

export { ESSigOperator };

/**
 * ECDSA アルゴリズムで署名の作成と検証を行うオペレータを定義する
 */
const ESSigOperator: SigOperator<ESAlg> = { sign, verify };

/**
 * ECDSA (alg)に従い、与えられたメッセージ(m)と秘密鍵(key) から署名を作成する。
 */
async function sign(alg: ESAlg, key: JWK<'EC', 'Priv'>, m: Uint8Array): Promise<JWSSignature> {
  const { keyAlg, sigAlg } = params(alg, key.crv);
  const k = await window.crypto.subtle.importKey('jwk', key as JsonWebKey, keyAlg, false, ['sign']);
  const s = await window.crypto.subtle.sign(sigAlg, k, m);
  return new Uint8Array(s) as JWSSignature;
}

/**
 * ECDSA (alg)に従い、与えられたメッセージ(m)と公開鍵(key) を署名(s)で検証する。
 */
async function verify(
  alg: ESAlg,
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

function params(alg: ESAlg, crv: JWACrv): { keyAlg: EcKeyImportParams; sigAlg: EcdsaParams } {
  return {
    keyAlg: { name: 'ECDSA', namedCurve: crv },
    sigAlg: { name: 'ECDSA', hash: 'SHA-' + alg.slice(2) },
  };
}

// --------------------END JWA EC algorithms --------------------
