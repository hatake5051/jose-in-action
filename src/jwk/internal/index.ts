// --------------------BEGIN JWK definition --------------------

import { Alg, JOSEHeader, KeyUse, Kty } from 'iana';
import {
  isJWAMACAlg,
  isJWASigAlg,
  JWAMACAlg,
  JWASigAlg,
  ktyFromJWAJWSAlg,
  KtyFromJWAJWSAlg,
} from 'jwa/sec3/alg';
import { equalsJWAJWK, exportJWAPublicKey, isJWAJWK, JWAJWK } from 'jwa/sec6/jwk';
import { isJWAKty, JWAKty } from 'jwa/sec6/kty';
import { BASE64URL, isObject } from 'utility';
import { isCommonJWKParams, validCommonJWKParams } from './common';
import { isX509SPKI, parseX509BASE64EncodedDER, validateSelfSignedCert } from './x509';

export { JWK, JWKSet, isJWKSet, isJWK, equalsJWK, validJWK, identifyKey, exportPublicKey };

/**
 * RFC7517#4
 * JSON Web Key は暗号鍵を表現する JSON オブジェクト。
 * Kty がなんであるか、また非対称暗号鍵の場合は公開鍵か秘密鍵かで具体的な型を指定できる
 */
type JWK<K extends Kty = Kty, A extends AsymKty = AsymKty> = K extends JWAKty
  ? JWAJWK<K, A>
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
  // kty を指定しないときは、最低限 JWK が持つべき情報を持っているか確認する
  if (kty == null) return isCommonJWKParams(arg);
  if (isJWAKty(kty)) return isJWAJWK(arg, kty, asym);
  return false;
}

function equalsJWK(l?: JWK, r?: JWK): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  if (isJWAKty(l.kty)) return equalsJWAJWK(l, r);
  return false;
}

/**
 * 秘密鍵から公開鍵情報を取り出す。
 */
function exportPublicKey<K extends 'RSA' | 'EC'>(priv: JWK<K, 'Priv'>): JWK<K, 'Pub'> {
  if (isJWAKty(priv.kty)) return exportJWAPublicKey(priv) as JWK<K, 'Pub'>;
  throw new EvalError(`${priv.kty} の公開鍵を抽出できなかった`);
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
const isJWKSet = (arg: unknown): arg is JWKSet =>
  isObject<JWKSet>(arg) && Array.isArray(arg.keys) && arg.keys.every((k) => isJWK(k));

/**
 * JWK が非対称鍵の場合、公開鍵か秘密鍵かのいずれかであるかを表す。
 */
type AsymKty = 'Pub' | 'Priv';

/**
 * Alg に応じた Kty を返す型
 */
type KtyFromAlg<A extends Alg> = A extends JWASigAlg | JWAMACAlg ? KtyFromJWAJWSAlg<A> : never;

/**
 * 引数 alg に応じた kty の値を返す関数
 */
const ktyFromAlg = (alg: Alg): Kty => {
  if (isJWASigAlg(alg) || isJWAMACAlg(alg)) return ktyFromJWAJWSAlg(alg);
  throw new TypeError(`${alg} に対応する kty がわからなかった`);
};

function identifyKey<A extends Alg>(
  set: JWKSet,
  h: Required<Pick<JOSEHeader<A>, 'alg'>> & Pick<JOSEHeader<A>, 'kid'>
): JWK<KtyFromAlg<A>> {
  for (const key of set.keys) {
    if (
      (isJWASigAlg(h.alg) || isJWAMACAlg(h.alg)) &&
      key.kty === ktyFromAlg(h.alg) &&
      key.kid === h.kid
    ) {
      return key as JWK<KtyFromAlg<A>>;
    }
  }
  throw RangeError(`JWKSet(${set}) から JOSEheader(${h}) に対応する鍵が存在しなかった`);
}

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
