import { Kty, KtyAsym } from '../iana';
import { CommomJWKParams, isCommonJWKParams } from './internal/common';
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

export {
  JWK,
  JWKSym,
  JWKPriv,
  JWKPub,
  JWKSet,
  isJWKSet,
  isJWK,
  isJWKSym,
  isJWKPub,
  isJWKPriv,
  validX5CinJWKPub,
};

/**
 * RFC7517#4
 * JSON Web Key は暗号鍵を表現する JSON オブジェクト。
 */
type JWK<K extends Kty> = CommomJWKParams<K>;

const isJWK = (arg: unknown): arg is JWK<Kty> => isCommonJWKParams(arg);

type JWKSym = octKey;

const isJWKSym = (arg: unknown): arg is JWKSym => isOctKey(arg);

type JWKPub<K extends KtyAsym> = K extends 'EC'
  ? ECPublicKey
  : K extends 'RSA'
  ? RSAPublicKey
  : never;

const isJWKPub = <K extends KtyAsym>(
  kty: K,
  arg: unknown
): arg is JWKPub<K> => {
  if (!isJWK(arg)) return false;
  if (kty !== arg.kty) return false;
  switch (arg.kty) {
    case 'EC':
      return isECPublicKey(arg);
    case 'RSA':
      return isRSAPublicKey(arg);
  }
};

async function validX5CinJWKPub<K extends KtyAsym>(
  jwk: JWKPub<K>
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

type JWKPriv<K extends KtyAsym> = K extends 'EC'
  ? ECPrivateKey
  : K extends 'RSA'
  ? RSAPrivateKey
  : never;

const isJWKPriv = <K extends KtyAsym>(
  kty: K,
  arg: unknown
): arg is JWKPriv<K> => {
  if (!isJWK(arg)) return false;
  if (kty !== arg.kty) return false;
  switch (arg.kty) {
    case 'EC':
      return isECPrivateKey(arg);
    case 'RSA':
      return isRSAPrivateKey(arg);
  }
};

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
  keys: JWK<Kty>[];
};

const isJWKSet = (arg: unknown): arg is JWKSet => {
  if (typeof arg !== 'object') return false;
  if (arg == null) return false;
  return 'keys' in arg && Array.isArray((arg as JWKSet).keys);
};
