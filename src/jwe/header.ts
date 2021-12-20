import { Alg, EncAlg, isAlg, isEncAlg } from 'iana/alg';
import { equalsJWK, isJWK, JWK } from 'jwk';
import { JWSJOSEHeaderParamNames } from 'jws/type';
import { isObject } from 'utility';

export type JWEJOSEHeaderParams = {
  /**
   * RFC7516#4.1.1 Algorithm Header Parameter
   * CEK の暗号化もしくは CEK を決定するために使用される。
   */
  alg: Alg<'JWE'>;
  /**
   * RFC7516#4.1.2 Encryption Algorithm Header Parameter
   * 平文を暗号化するためのコンテンツ暗号化アルゴリズムを識別する。
   */
  enc: EncAlg;
  /**
   * RFC7516#4.1.3 Compression Algorithm Header Parameter
   * 暗号化する前にプレーンテキストに適用される圧縮アルゴリズムを表す
   */
  zip?: 'DEF';
  /**
   * RFC7516#4.1.4 JWK Set URL Header Parameter
   * JWK Set のリソースを参照する URI でこのうちの１つはこの JWE が暗号化された公開鍵が含まれる。
   * JWE を復号するために必要な秘密鍵を判別するために使う。
   */
  jku?: string;
  /**
   * RFC7516#4.1.5 JWK Header Parameter
   * JWE を暗号化した公開鍵が含まれる。
   * JWE を復号するために必要な秘密鍵を判別するために使う。
   */
  jwk?: JWK;
  /**
   * RFC7516#4.1.6 Key ID Header Parameter
   * JWE を暗号化した公開鍵を参照するためのヒント。
   * originator は JWE recipients に鍵の変更を通知できる
   */
  kid?: string;
  /**
   * RFC7516#4.1.7 X.509 URL Header Parameter
   * JWE の暗号化に使われた公開鍵に対応する X.509 公開鍵証明書もしくはその証明書チェーンを参照できる URI
   * JWE を復号するために必要な秘密鍵を判別するために用いる。
   */
  x5u?: string;
  /**
   * RFC7516#4.1.8 X.509 Certificate Chain Header Parameter
   * JWE の暗号化に使われた鍵に対応する X.509 公開鍵証明書もしくはその証明書チェーン。
   * JWE を復号するために必要な秘密鍵を判別するために用いる。
   */
  x5c?: string[];
  /**
   * RFC7516#4.1.9 X.509 Certificate SHA-1 Thumbprint Header Parameter
   * 暗号化に使った公開鍵に対応する X.509 証明書のハッシュ値。
   * JWE を復号するために必要な秘密鍵を判別するために用いる。
   */
  x5t?: string;
  /**
   * RFC7516#4.1.10 X.509 Certificate SHA-256 Thumbprint Header Parameter
   * 暗号化に使った公開鍵に対応する X.509 証明書のハッシュ値。
   * JWE を復号するために必要な秘密鍵を判別するために用いる。
   */
  'x5t#S256'?: string;
  /**
   * RFC7516#4.1.11 Type Header Parameter
   * JWE 全体のメディアタイプを宣言する
   * application/jose で JWE Compact Serialization であることを
   * application/jose+json で JWE JSON Serialization であることを示せる。
   * コンパクトに表現するために application/ prefix は省略できる。
   * JWS の実装では特に使用しない、 JWS を使うアプリ側で使うかもね
   */
  typ?: string;
  /**
   * RFC7516#4.1.12 Content Type Header Parameter
   * JWE を使うアプリ側が使う、 secured content (payload) のメディアタイプ宣言
   */
  cty?: string;
  /**
   * RFC7516#4.1.13 Critical Header Parameter
   * RFC7516 や RFC7518 で定義されていないヘッダーを使いたくて、それの理解と処理を必須にしたい時、
   * そのヘッダー名をリストで記載。
   */
  crit?: string[];
};

export const JWEJOSEHeaderParamNames = [
  'alg',
  'enc',
  'zip',
  'jku',
  'jwk',
  'kid',
  'x5u',
  'x5c',
  'x5t',
  'x5t#S256',
  'typ',
  'cty',
  'crit',
] as const;

export const isPartialJWEJOSEHeaderParams = (arg: unknown): arg is Partial<JWEJOSEHeaderParams> =>
  isObject<Partial<JWEJOSEHeaderParams>>(arg) &&
  JWEJOSEHeaderParamNames.every(
    (n) =>
      arg[n] == null ||
      (n === 'alg'
        ? isAlg(arg[n], 'JWE')
        : n === 'enc'
        ? isEncAlg(arg[n])
        : n === 'jwk'
        ? isJWK(arg[n])
        : n === 'x5c' || n === 'crit'
        ? Array.isArray(arg[n]) && (arg[n] as unknown[]).every((m) => typeof m === 'string')
        : typeof arg[n] === 'string')
  );

export function equalsJWEJOSEHeaderParams(
  l?: Partial<JWEJOSEHeaderParams>,
  r?: Partial<JWEJOSEHeaderParams>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return JWSJOSEHeaderParamNames.every((n) => {
    if (l[n] == null && r[n] == null) return true;
    if (l[n] == null || r[n] == null) return false;
    switch (n) {
      case 'jwk':
        return equalsJWK(l[n], r[n]);
      case 'x5c':
      case 'crit':
        return (
          new Set(l[n]).size === new Set(r[n]).size &&
          l[n]?.every((l) => r[n]?.some((r) => r === l))
        );
      default:
        return l[n] === r[n];
    }
  });
}
