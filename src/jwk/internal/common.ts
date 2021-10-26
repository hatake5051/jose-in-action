// --------------------BEGIN JWK common parameters --------------------

import { Alg, isAlg, isKeyOps, isKeyUse, isKty, KeyOps, KeyUse, Kty } from '../../iana';

export { CommomJWKParams, isCommonJWKParams, validCommonJWKParams };

/**
 * JWK が持つ共通パラメータを表す。
 */
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

/**
 * CommonJWKParams の型ガード。型で表現していない JWK の制限は validJWK でチェックする。
 */
const isCommonJWKParams = (arg: unknown): arg is CommomJWKParams<Kty> => {
  // CommJWKParams は null ではないオブジェクト
  if (typeof arg !== 'object' || arg == null) return false;
  // CommonJWKParams は kty をもち、その値は IANA に登録済みの値である
  if (!('kty' in arg) || !isKty((arg as { kty: unknown }).kty)) return false;
  // CommonJWKParams は use を持つことがあり、持つ場合はその値が IANA に登録済みの値である
  if ('use' in arg && !isKeyUse((arg as { use: unknown }).use)) return false;
  // CommonJWKParams は key_ops を持つことがあり、持つ場合はその値が IANA に登録済みの値である
  if ('key_ops' in arg) {
    const ops = (arg as { key_ops: unknown }).key_ops;
    if (!Array.isArray(ops) || !ops.every((o) => isKeyOps(o))) return false;
  }
  // CommonJWKParams は alg を持つことがあり、持つ場合はその値が IANA に登録済みの値である
  if ('alg' in arg && !isAlg((arg as { alg: unknown }).alg)) return false;
  return true;
};

/**
 * CommonJWKParams が RFC7517 に準拠しているか確認する
 */
function validCommonJWKParams(params: CommomJWKParams<Kty>): boolean {
  if (params.key_ops != null) {
    // key_ops と use は一緒に使うべきではない (SHOULD NOT)
    if (params.use != null) return false;
    const set = new Set(params.key_ops);
    // key_ops は高々２の配列で、重複する値を含めてはならない(MUST NOT)
    if (params.key_ops.length > 2 || params.key_ops.length !== set.size) return false;
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

// --------------------END JWK common parameters --------------------
