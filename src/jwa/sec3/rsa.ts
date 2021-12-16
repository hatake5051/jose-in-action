// --------------------BEGIN JWA RSA algorithms --------------------

import { JWK } from 'jwk';
import { SigOperator } from 'jws/interface';
import { JWSSignature } from 'jws/type';
import { BASE64URL_DECODE } from 'utility';

export { RSAlg, isRSAlg, PSAlg, isPSAlg, RSASigOperator };

/**
 * RSASSA-PKCS1-v1.5 か RSA-PSS アルゴリズムで署名の作成と検証を行うオペレータを定義する
 */
const RSASigOperator: SigOperator<RSAlg | PSAlg> = {
  sign,
  verify,
};

/**
 * RFC7518#3.3.  Digital Signature with RSASSA-PKCS1-v1_5 のアルゴリズム識別子を列挙する。
 */
type RSAlg = typeof rsAlgList[number];

/**
 * 引数が RSA-PKCS1-v1.5 アルゴリズム識別子か確認する。
 */
const isRSAlg = (arg: unknown): arg is RSAlg =>
  typeof arg === 'string' && rsAlgList.some((a) => a === arg);

const rsAlgList = ['RS256', 'RS384', 'RS512'] as const;

/**
 * RFC7518#3.5.  Digital Signature with RSASSA-PSS のアルゴリズム識別子を列挙する。
 */
type PSAlg = typeof psAlgList[number];

/**
 * 引数が RSA-PSS アルゴリズム識別子か確認する。
 */
const isPSAlg = (arg: unknown): arg is PSAlg =>
  typeof arg === 'string' && psAlgList.some((a) => a === arg);

const psAlgList = ['PS256', 'PS384', 'PS512'] as const;

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
