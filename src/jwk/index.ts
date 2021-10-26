// --------------------BEGIN JWK definition --------------------

import { KeyUse, Kty } from '../iana';
import { BASE64URL } from '../util';
import { isCommonJWKParams, validCommonJWKParams } from './internal/common';
import { ECPrivateKey, ECPublicKey, isECPrivateKey, isECPublicKey } from './internal/ec';
import { isOctKey, octKey } from './internal/oct';
import { isRSAPrivateKey, isRSAPublicKey, RSAPrivateKey, RSAPublicKey } from './internal/rsa';
import { isX509SPKI, parseX509BASE64EncodedDER, validateSelfSignedCert } from './internal/x509';

export { JWK, JWKSet, isJWKSet, isJWK, validJWK };

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
      if (asym === undefined) return isRSAPublicKey(arg) || isRSAPrivateKey(arg);
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
 * JWK が非対称鍵の場合、公開鍵か秘密鍵かのいずれかであるかを表す。
 */
type AsymKty = 'Pub' | 'Priv';

/**
 * 型で表現しきれない JWK の条件を満たすか確認する。
 * options に渡された条件を jwk が満たすか確認する
 * options.x5c を渡すことで、 jwk.x5c があればそれを検証する。
 * options.x5c.selfSigned = true にすると、x5t が自己署名証明書だけを持つか確認し、
 * 署名が正しいか確認する。また jwk パラメータと同じ内容が書かれているか確認する。
 */
async function validJWK<K extends Kty, A extends AsymKty>(
  jwk: JWK<K, A>,
  options: {
    use?: KeyUse;
    x5c?: {
      selfSigned?: boolean;
    };
  }
): Promise<boolean> {
  if (!validCommonJWKParams(jwk)) return false;
  if (options == null) return true;
  if (options.use != null) {
    if (options.use !== jwk.use) return false;
  }
  if (options.x5c != null) {
    const err = await validJWKx5c(jwk, options.x5c?.selfSigned);
    if (err != null) {
      throw EvalError(err);
    }
  }
  return true;
}

type JWKValidationError =
  | 'JWK.x5c parameter not found'
  | 'JWK.x5c is self-signed certificate'
  | 'JWK.x5c[0] does not match with JWK parameteres'
  | 'JWK.x5c does not support symmetric key representation'
  | 'JWK.x5c Signature Verification Error';

async function validJWKx5c<K extends Kty>(
  jwk: JWK<K, 'Pub' | 'Priv'>,
  selfSigned = false
): Promise<JWKValidationError | undefined> {
  if (jwk.x5c == null) return 'JWK.x5c parameter not found';
  if (jwk.x5c.length === 1 && !selfSigned) return 'JWK.x5c is self-signed certificate';
  // The key in the first certificate MUST match the public key represented by other members of the JWK. (RFC7517)
  // jwk.x5c[0] が表現する公開鍵はその jwk が表現する値と同じでなければならない
  const crt1 = parseX509BASE64EncodedDER(jwk.x5c[0]);
  switch (jwk.kty) {
    case 'RSA':
      if (
        crt1.tbs.spki.kty === 'RSA' &&
        isX509SPKI(crt1.tbs.spki, 'RSA') &&
        jwk.n === BASE64URL(crt1.tbs.spki.n) &&
        jwk.e === BASE64URL(crt1.tbs.spki.e)
      ) {
        break;
      }
      return 'JWK.x5c[0] does not match with JWK parameteres';
    case 'EC':
      if (
        crt1.tbs.spki.kty === 'EC' &&
        isX509SPKI(crt1.tbs.spki, 'EC') &&
        jwk.x === BASE64URL(crt1.tbs.spki.x) &&
        jwk.y === BASE64URL(crt1.tbs.spki.y)
      ) {
        break;
      }
      return 'JWK.x5c[0] does not match with JWK parameteres';
    case 'oct':
      return 'JWK.x5c does not support symmetric key representation';
  }

  if (jwk.x5c.length > 1)
    throw EvalError('証明書チェーンが１の長さで、かつ自己署名の場合のみ実装している');
  const crt = parseX509BASE64EncodedDER(jwk.x5c[0]);
  if (!(await validateSelfSignedCert(crt))) {
    return 'JWK.x5c Signature Verification Error';
  }
}

// --------------------END JWK definition --------------------
