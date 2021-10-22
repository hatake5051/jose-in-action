import { isKty, KeyOps, KeyUse, Kty } from '../../iana';

type CommomJWKParams<K extends Kty> = {
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
  alg?: string;
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
const commonJWKParams = [
  'kty',
  'use',
  'key_ops',
  'alg',
  'kid',
  'x5u',
  'x5c',
  'x5t',
  'x5t#S256',
];

const isCommonJWKParams = (arg: unknown): arg is CommomJWKParams<Kty> => {
  if (typeof arg !== 'object' || arg == null) return false;
  if ('kty' in arg) {
    return isKty((arg as { kty: unknown }).kty);
  }
  return false;
};

export { CommomJWKParams, isCommonJWKParams };
