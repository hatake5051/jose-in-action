// --------------------BEGIN JWA RSA algorithms --------------------

import { JWK } from 'jwk';
import { SigOperator } from 'jws/interface';
import { JWSSignature } from 'jws/type';
import { BASE64URL_DECODE } from 'utility';
import { isRSAlg, PSAlg, RSAlg } from './alg';

export { RSASigOperator };

/**
 * RSASSA-PKCS1-v1.5 か RSA-PSS アルゴリズムで署名の作成と検証を行うオペレータを定義する
 */
const RSASigOperator: SigOperator<RSAlg | PSAlg> = {
  sign,
  verify,
};

/**
 * RSASSA-PKCS1-v1.5 か RSA-PSS アルゴリズム(alg)に従い、与えられたメッセージ(m)と秘密鍵(key) から署名を作成する。
 * 計算を行う前に、鍵長が十分かどうか判定を行う。
 */
async function sign(
  alg: RSAlg | PSAlg,
  key: JWK<'RSA', 'Priv'>,
  m: Uint8Array
): Promise<JWSSignature> {
  const { keyAlg, sigAlg } = params(alg);
  if (BASE64URL_DECODE(key.n).length * 8 < 2048 && BASE64URL_DECODE(key.d).length * 8 < 2048) {
    // キーサイズが 2048 bit 以上であることが MUST (RFC7518#3.3)
    throw new EvalError(`RSA sig では鍵長が 2048 以上にしてください`);
  }

  const k = await window.crypto.subtle.importKey('jwk', key as JsonWebKey, keyAlg, false, ['sign']);
  const s = await window.crypto.subtle.sign(sigAlg, k, m);
  return new Uint8Array(s) as JWSSignature;
}

/**
 * RSASSA-PKCS1-v1.5 か RSA-PSS アルゴリズム(alg)に従い、与えられたメッセージ(m)と公開鍵(key) を署名(sig)で検証する。
 * 計算を行う前に、鍵長が十分かどうか判定を行う。
 */
async function verify(
  alg: RSAlg | PSAlg,
  key: JWK<'RSA', 'Pub'>,
  m: Uint8Array,
  sig: JWSSignature
): Promise<boolean> {
  if (BASE64URL_DECODE(key.n).length * 8 < 2048) {
    // キーサイズが 2048 bit 以上であることが MUST (RFC7518#3.3)
    throw new EvalError(`RSA sig では鍵長が 2048 以上にしてください`);
  }

  const { keyAlg, sigAlg } = params(alg);

  const k = await window.crypto.subtle.importKey('jwk', key as JsonWebKey, keyAlg, false, [
    'verify',
  ]);
  const s = await window.crypto.subtle.verify(sigAlg, k, sig, m);
  return s;
}

function params(alg: PSAlg | RSAlg): {
  keyAlg: RsaHashedImportParams;
  sigAlg: AlgorithmIdentifier | RsaPssParams;
} {
  let name: string, sigAlg: AlgorithmIdentifier | RsaPssParams;
  if (isRSAlg(alg)) {
    name = 'RSASSA-PKCS1-v1_5';
    sigAlg = name;
  } else {
    // isPSAlg(alg) === true
    name = 'RSA-PSS';
    // ソルト値のサイズはハッシュ関数の出力と同じサイズ (RFC7518#3.5)
    sigAlg = { name, saltLength: parseInt(alg.slice(2)) / 8 };
  }
  const keyAlg: RsaHashedImportParams = { name, hash: 'SHA-' + alg.slice(2) };
  return { keyAlg, sigAlg };
}

// --------------------END JWA RSA algorithms --------------------
