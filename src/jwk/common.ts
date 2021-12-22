import { Alg, isAlg, isEncAlg } from 'iana/alg';
import { isKeyOps, isKeyUse, KeyOps, KeyUse } from 'iana/key_ops';
import { isKty, Kty } from 'iana/kty';
import { isObject } from 'utility';

export {
  CommonJWKParams,
  isCommonJWKParams,
  isPartialCommonJWKParams,
  equalsCommonJWKParams,
  exportCommonJWKParams,
};

/**
 * JWK が持つ共通パラメータを表す。
 * K を指定すれば kty パラメータをその型に制限できる
 */
type CommonJWKParams<K extends Kty = Kty> = {
  /**
   * RFC7517#4.1
   * JWK Key Type parameter はこの鍵を使う暗号アルゴリズムを識別する。
   * JWK では必須パラメータ。
   * 値として IANA レジストリに定義されているもののいずれか、もしくは Collision-Resistant Name をもつ。
   * 今回は IANA レジストリに定義されているもののみを受け取ることにした。
   */
  kty: K;
  /**
   * RFC7517#4.2
   * JWK Public Key Use parameter はこの公開鍵の使用目的を識別する。
   * 値として IANA レジストリに定義されているもののいずれか、もしくは当事者間で合意された文字列をもつ。
   * 今回は IANA レジストリに定義されているもののみを受け取ることにした。
   */
  use?: KeyUse;
  /**
   * RFC7517#4.3
   * JWK Key Operations parameter はこの鍵で意図された暗号操作を識別する。
   * 値として IANA レジストリに定義されているもののいずれか、もしくは当事者間で合意された文字列をもつ。
   * 今回は IANA レジストリに定義されているもののみを受け取ることにした。
   */
  key_ops?: KeyOps[];
  /**
   * RFC7517#4.4
   * JWK Algorithm parameter はこの鍵を使う時に目的としたアルゴリズムを識別する。
   * 値として IANA レジストリに定義されているもののいずれか、もしくは当事者間で合意された文字列をもつ。
   */
  alg?: Alg;
  /**
   * RFC7517#4.5
   * JWK Key ID parameter は特定の鍵を照合するために用いられる。
   */
  kid?: string;
  /**
   * RFC7517#4.6
   * X.509 URL parameter は X.509 公開鍵証明書もしくは証明書チェーンのリソースを参照する URI である。
   * 使われている例を見たことがない...
   */
  x5u?: string;
  /**
   * RFC7517#4.7
   * X.509 Certificate Chain parameter はひとつ以上の証明書チェーンが含まれる。
   * 各証明書の値は X.509 証明書の DER エンコードされたものを BASE64 (BASE64URL ではない) エンコードしてある。
   */
  x5c?: string[];
  /**
   * RFC7517#4.8
   * X.509 Certificate SHA-1 Thumbprint parameter は X509 証明書の DER エンコードされたものの SHA-1 ダイジェストである。
   */
  x5t?: string;
  /**
   * RFC7517#4.9
   * X.509 Certificate SHA-256 Thumbprint parameter は X.509 証明書の DER エンコードされたものの SHA-256 ダイジェストである。
   */
  'x5t#S256'?: string;
};

const CommonJWKParamNames = [
  'kty',
  'use',
  'key_ops',
  'alg',
  'kid',
  'x5u',
  'x5c',
  'x5t',
  'x5t#S256',
] as const;

/**
 * CommonJWKParams の型ガード。型で表現していない JWK の制限は validJWK でチェックする。
 */
const isPartialCommonJWKParams = (arg: unknown): arg is Partial<CommonJWKParams> =>
  isObject<CommonJWKParams>(arg) &&
  CommonJWKParamNames.every((n) => {
    if (arg[n] == null) return true;
    switch (n) {
      case 'kty':
        return isKty(arg[n]);
      case 'use':
        return isKeyUse(arg[n]);
      case 'key_ops':
        return Array.isArray(arg.key_ops) && arg.key_ops.every((x) => isKeyOps(x));
      case 'alg':
        return isAlg(arg[n]) || isEncAlg(arg[n]);
      case 'x5c':
        return Array.isArray(arg['x5c']) && arg['x5c'].every((s: unknown) => typeof s === 'string');
      default:
        return typeof arg[n] === 'string';
    }
  });

function isCommonJWKParams<K extends Kty>(arg: unknown, kty?: K): arg is CommonJWKParams<K> {
  if (!isPartialCommonJWKParams(arg)) return false;
  if (!arg.kty || (kty && arg.kty !== kty)) return false;
  if (arg.key_ops != null) {
    // key_ops と use は一緒に使うべきではない (SHOULD NOT)
    if (arg.use != null) return false;
    const set = new Set(arg.key_ops);
    // key_ops は高々２の配列で、重複する値を含めてはならない(MUST NOT)
    if (arg.key_ops.length > 2 || arg.key_ops.length !== set.size) return false;
    if (set.size === 2) {
      // かつ、要素は["sign", "verify"], ["encrypt", "decrypt"], ["wrapKey", "unwrapKey"] のバリエーションのみ(SHOULD)
      // 疑問: なぜ ["deriveBit", "deriveKey"] の組み合わせはなぜダメなのか？教えて欲しい...
      if (
        !(
          (set.has('sign') && set.has('verify')) ||
          (set.has('encrypt') && set.has('decrypt')) ||
          (set.has('wrapKey') && set.has('unwrapKey'))
        )
      )
        return false;
    }
  }
  return true;
}

function equalsCommonJWKParams(
  l?: Partial<CommonJWKParams>,
  r?: Partial<CommonJWKParams>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return CommonJWKParamNames.every((n) => {
    if (l[n] == null && r[n] == null) return true;
    if (l[n] == null || r[n] == null) return false;
    switch (n) {
      case 'key_ops':
      case 'x5c': {
        return (
          new Set(l[n]).size === new Set(r[n]).size &&
          l[n]?.every((l) => r[n]?.some((r) => r === l))
        );
      }
      default: {
        return l[n] === r[n];
      }
    }
  });
}

function exportCommonJWKParams(jwk: CommonJWKParams): CommonJWKParams {
  let ans: Partial<CommonJWKParams> = {};
  CommonJWKParamNames.forEach((n) => {
    ans = { ...ans, [n]: jwk[n] };
  });
  if (isCommonJWKParams(ans)) return ans;
  throw new TypeError('CommonJWKParams を抽出できなかった');
}
