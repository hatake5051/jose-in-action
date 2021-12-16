import { Alg, isAlg } from 'iana/alg';
import { JOSEHeader } from 'iana/header';
import { equalsJWK, isJWK, JWK } from 'jwk';
import { isObject } from 'utility';

/**
 * 保護されるオクテット列（別名メッセージ）。
 * ペイロードは任意のオクテット列を含めることができる。
 */
export type JWSPayload = Uint8Array & { _brand: 'JWSPayload' };

/**
 * JWS Protected Header と JWS Payload に対するデジタル署名もしくは MAC。
 */
export type JWSSignature = Uint8Array & { _brand: 'JWSSignature' };

/**
 * JWS Signature によって完全性を保護されるヘッダーパラメータを含む JSON オブジェクト。
 */
export type JWSProtectedHeader = JOSEHeader<'JWS'> & { _brand: 'JWSProtectedHeader' };

/**
 * 完全性を保護されないヘッダーパラメータを含む JSON オブジェクト。
 */
export type JWSUnprotectedHeader = JOSEHeader<'JWS'> & { _brand: 'JWSUnprotectedHeader' };

/**
 * RFC7515#4
 * JWS において JOSE Header のプロパティは、JWS Protected Header と JWS Payload に適用される
 * デジタル署名や MAC やオプションで JWS の追加プロパティを記述する。
 */
export type JWSJOSEHeader = {
  /**
   * RFC7515#4.1.1 Algorithm Header Parameter
   * JWS を保護するために使う暗号アルゴリズムを識別する。
   * IANA に登録済みのものだけ有効とした。
   */
  alg: Alg<'JWS'>;
  /**
   * RFC7515#4.1.2 JWK Set URL Header Parameter
   * JWK Set のリソースを参照する URI でこのうちの１つはこの JWS に署名するために使われた署名鍵に対応する。
   */
  jku?: string;
  /**
   * RFC7515#4.1.2 JWK Header Parameter
   * JWS の署名に使った鍵に対応する検証鍵を JWK で表現したもの。
   */
  jwk?: JWK;
  /**
   * RFC7515#4.1.4 Key ID Header Parameter
   * JWS を保護するために用いた鍵を示すヒント。
   * JWK と一緒に用いるときは、 JWK.kid パラメータと一致させるために使う。
   */
  kid?: string;
  /**
   * RFC7515#4.1.5 X.509 URL Header Parameter
   * JWS の署名に使われた鍵に対応する X.509 公開鍵証明書もしくはその証明書チェーンを参照できる URI
   */
  x5u?: string;
  /**
   * RFC7515#4.1.6 X.509 Certificate Chain Header Parameter
   * JWS の署名に使われた鍵に対応する X.509 公開鍵証明書もしくはその証明書チェーン。
   * 配列の0番目が署名に使われた鍵に対応する公開鍵証明書である。
   */
  x5c?: string[];
  /**
   * RFC7515#4.1.7 X.509 Certificate SHA-1 Thumbprint Header Parameter
   * 署名に使った鍵に対応する X.509 証明書のハッシュ値。
   * SHA-1(BASE64URL(DER(Certificate))) である。
   */
  x5t?: string;
  /**
   * RFC7515#4.1.8 X.509 Certificate SHA-256 Thumbprint Header Parameter
   * 署名に使った鍵に対応する X.509 証明書のハッシュ値。
   * SHA-256(BASE64URL(DER(Certificate))) である。
   */
  'x5t#S256'?: string;
  /**
   * RFC7515#4.1.9 Type Header Parameter
   * JWS 全体のメディアタイプを宣言する
   * application/jose で JWS Compact Serialization であることを
   * application/jose+json で JWS JSON Serialization であることを示せる。
   * コンパクトに表現するために application/ prefix は省略できる。
   * JWS の実装では特に使用しない、 JWS を使うアプリ側で使うかもね
   */
  typ?: string;
  /**
   * RFC7515#4.1.10 Content Type Header Parameter
   * JWS を使うアプリがわが使う、 secured content (payload) のメディアタイプ宣言
   */
  cty?: string;
  /**
   * RFC7515#4.1.11 Critical Header Parameter
   * RFC7515 や RFC7518 で定義されていないヘッダーを使いたくて、それの理解と処理を必須にしたい時、
   * そのヘッダー名をリストで記載。
   */
  crit?: string[];
};

/**
 * 引数が JWSJOSEHeader か確認する。
 * JWS で定義されている JWSJOSEHeader パラメータをもち、 alg を持っているか確認する。
 */
export const isJWSJOSEHeader = (arg: unknown): arg is JWSJOSEHeader =>
  isPartialJWSJOSEHeader(arg) && arg.alg != null;

export const JWSJOSEHeaderParamNames = [
  'alg',
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

/**
 * 引数が Partial<JWSJOSEHeader> か確認する。
 * isJWSJOSEHeader は alg が値を持っているか確認するが、これでは undefined でも良いとしている。
 */
export const isPartialJWSJOSEHeader = (arg: unknown): arg is Partial<JWSJOSEHeader> =>
  isObject<Partial<JWSJOSEHeader>>(arg) &&
  JWSJOSEHeaderParamNames.every(
    (n) =>
      arg[n] == null ||
      (n === 'alg'
        ? isAlg(arg[n], 'JWS')
        : n === 'jwk'
        ? isJWK(arg[n])
        : n === 'x5c' || n === 'crit'
        ? Array.isArray(arg[n]) && (arg[n] as unknown[]).every((m) => typeof m === 'string')
        : typeof arg[n] === 'string')
  );

/**
 * ２つの JWSJOSEHEader が同じか判定する
 */
export function equalsJWSJOSEHeader(
  l?: Partial<JWSJOSEHeader>,
  r?: Partial<JWSJOSEHeader>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of JWSJOSEHeaderParamNames) {
    const ln = l[n];
    const rn = r[n];
    if (ln == null && rn == null) continue;
    if (ln == null || rn == null) return false;
    switch (n) {
      case 'jwk': {
        const ll = ln as JWK;
        const rr = rn as JWK;
        if (equalsJWK(ll, rr)) continue;
        return false;
      }
      case 'x5t':
      case 'crit': {
        const ll = ln as string[];
        const rr = rn as string[];
        if (new Set(ll).size === new Set(rr).size && ll.every((l) => rr.includes(l))) continue;
        return false;
      }
      default: {
        const ll = ln as string;
        const rr = rn as string;
        if (ll === rr) continue;
        return false;
      }
    }
  }
  return true;
}

/**
 * JWS を URL-safe な文字列をする serialization
 * 署名は１つだけしか表現できず、 Unprotected Header も表現できない
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * で表現する。
 */
export type JWSCompactSerialization = string;

/**
 * JSON で Serialization する
 * コンパクトでもないし、 url-safe でもないが表現に制限はない。
 */
export type JWSJSONSerialization = {
  /**
   * BASE64URL(JWS Payload)
   */
  payload: string;
  /**
   * 署名を表現するオブジェクトの配列
   */
  signatures: {
    /**
     * BASE64URL(JWS Signature)
     */
    signature: string;
    /**
     * UNprotected Header があればそのまま JSON でシリアライズ。
     * ないときは存在してはならない。
     */
    header?: JWSUnprotectedHeader;
    /**
     * Protected Header があれば BASE64URL(UTF8(JWS Protected Header)) デシリアライズ。
     * ないときは存在してはならない。
     */
    protected?: string;
  }[];
};

/**
 * 署名が１つだけの時に、JSON serialization は平滑化できる。
 * signatures は存在してはならない。
 */
export type JWSFlattenedJSONSerialization = {
  payload: string;
  signature: string;
  header?: JWSUnprotectedHeader;
  protected?: string;
};
