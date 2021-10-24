import { Kty } from '../iana';
import { isCommonJWKParams } from './internal/common';
import {
  ECPrivateKey,
  ECPublicKey,
  isECPrivateKey,
  isECPublicKey,
} from './internal/ec';
import { isOctKey, octKey } from './internal/oct';
import {
  isRSAPrivateKey,
  isRSAPublicKey,
  RSAPrivateKey,
  RSAPublicKey,
} from './internal/rsa';
import {
  parseX509BASE64EncodedDER,
  validateSelfSignedCert,
} from './internal/x509';

export { JWK, JWKSet, isJWKSet, isJWK, validJWK };

type AsymKty = 'Pub' | 'Priv';

/**
 * RFC7517#4
 * JSON Web Key は暗号鍵を表現する JSON オブジェクト。
 * Kty がなんであるか、また非対称暗号鍵の場合は公開鍵か秘密鍵かで具体的な型を指定できる
 */
type JWK<K extends Kty, A extends AsymKty> = K extends 'oct'
  ? octKey
  : K extends 'EC'
  ? A extends 'Pub'
    ? ECPublicKey
    : A extends 'Priv'
    ? ECPrivateKey
    : ECPublicKey | ECPrivateKey
  : K extends 'RSA'
  ? A extends 'Pub'
    ? RSAPublicKey
    : A extends 'Priv'
    ? RSAPrivateKey
    : RSAPublicKey | RSAPrivateKey
  : never;

/**
 * 引数が JWK オブジェクトであるかどうか確認する。
 * kty を指定するとその鍵タイプの JWK 形式を満たすか確認する。
 * asym を指定すると非対称暗号鍵のうち指定した鍵（公開鍵か秘密鍵）かであるかも確認する。
 */
function isJWK<K extends Kty, A extends AsymKty>(
  arg: unknown,
  kty?: K,
  asym?: A
): arg is JWK<K, A> {
  switch (kty) {
    // kty を指定しないときは、最低限 JWK が持つべき情報を持っているか確認する
    case undefined:
      return isCommonJWKParams(arg);
    case 'oct':
      return isOctKey(arg);
    case 'EC':
      if (asym === undefined) return isECPublicKey(arg) || isECPrivateKey(arg);
      if (asym === 'Pub') return isECPublicKey(arg);
      return isECPrivateKey(arg);
    case 'RSA':
      if (asym === undefined)
        return isRSAPublicKey(arg) || isRSAPrivateKey(arg);
      if (asym === 'Pub') return isRSAPublicKey(arg);
      return isRSAPrivateKey(arg);
    default:
      return false;
  }
}

/**
 * RFC7517#5
 * JWK Set は複数の JWK を表現する JSON オブジェクトである。
 */
type JWKSet = {
  /**
   * RFC7517#5.1
   * keys parameter は JWK の配列を値としてもつ。
   * デフォルトでは、 JWK の順序は鍵の優先順位を表していないが、アプリケーションによっては持たせても良い。
   */
  keys: JWK<Kty, AsymKty>[];
};

/**
 * 引数が JWK Set かどうか判定する.
 * keys パラメータが存在して、その値が JWK の配列なら OK
 */
const isJWKSet = (arg: unknown): arg is JWKSet => {
  if (typeof arg !== 'object') return false;
  if (arg == null) return false;
  if ('keys' in arg) {
    const a = arg as { keys: unknown };
    if (Array.isArray(a.keys)) {
      const l = a.keys as Array<unknown>;
      for (const k of l) {
        if (!isJWK(k)) return false;
      }
      return true;
    }
  }
  return false;
};

/**
 * options に渡された条件を jwk が満たすか確認する
 * options.x5c を渡すことで、 jwk.x5c があればそれを検証する。
 * options.x5c.selfSigned = true にすると、x5t が自己署名証明書だけを持つか確認し、
 * 署名が正しいか確認する。また jwk パラメータと同じ内容が書かれているか確認する。
 */
async function validJWK<K extends Kty, A extends AsymKty>(
  jwk: JWK<K, A>,
  options: {
    x5c?: {
      selfSigned?: boolean;
    };
  }
): Promise<boolean> {
  if (options == null) return true;
  if (options.x5c != null) {
    if (options.x5c.selfSigned && !validX5C(jwk)) return false;
  }
  return true;
}

async function validX5C<K extends Kty>(
  jwk: JWK<K, 'Pub' | 'Priv'>
): Promise<boolean> {
  if (jwk.x5c == null) return true;
  if (jwk.x5c.length > 1)
    throw EvalError(
      '証明書チェーンが１の長さで、かつ自己署名の場合のみ実装している'
    );
  const crt = parseX509BASE64EncodedDER(jwk.x5c[0]);
  if (!(await validateSelfSignedCert(crt))) {
    return false;
  }
  // X.509 crt と jwk の値の比較をする
  if (jwk.kty === 'RSA') {
    let keyAlg;
    if (crt.sigAlg.join('.') === '1.2.840.113549.1.1.5') {
      // sha1-with-rsa-signature とか sha1WithRSAEncryption
      keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' };
    } else if (crt.sigAlg.join('.') === '1.2.840.113549.1.1.11') {
      // sha256WithRSAEncryption
      keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    } else {
      throw EvalError(`validateSelfSignedCert の実装よりここには到達しない`);
    }
    const pubkey = await window.crypto.subtle.importKey(
      'spki',
      crt.tbs.spki,
      keyAlg,
      true,
      ['verify']
    );
    const crt_jwk = await window.crypto.subtle.exportKey('jwk', pubkey);
    return jwk.n === crt_jwk.n && jwk.e === crt_jwk.e;
  }
  if (jwk.kty === 'EC') {
    throw EvalError(`EC鍵を持つ x509crt の検証は未実装`);
  }
  return false;
}
