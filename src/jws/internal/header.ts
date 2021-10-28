import { equalsJWK, isJWK, JWK } from '../../jwk';
import { isObject } from '../../util';
import { isJWSAlg, JWSAlg } from './types';

export {
  JWSHeader,
  JWSProtectedHeader,
  isJWSProtectedHeader,
  JWSUnprotectedHeader,
  isJWSUnprotectedHeader,
  JWSJOSEHeader,
  equalsJWSJOSEHeader,
  isJWSJOSEHeader,
};

/**
 * JWS では JOSE Header は JWS Protected Header と JWS Unprotected Header の union で表現されるが、
 * 内部構造としてヘッダーパラメータが Protected かどうかという情報を保持し続けるためにクラスで定義している。
 * p と u のいずれか一方は存在することが必要で、どちらかには alg パラメータが含まれている
 */
class JWSHeader {
  private p?: JWSProtectedHeader;
  private u?: JWSUnprotectedHeader;
  private h: JWSJOSEHeader;

  constructor(p?: JWSProtectedHeader, u?: JWSUnprotectedHeader) {
    const h = { ...u, ...p };
    if (!isJWSJOSEHeader(h))
      throw new TypeError('JOSE Header for JWS に必要なパラメータが不足している');
    this.h = h;
    this.p = p;
    this.u = u;
  }

  /**
   * JWS Protected Header と JWS Unprotected Header の Union を返す
   */
  get JOSEHeader(): JWSJOSEHeader {
    return this.h;
  }

  /**
   * JWS Protected Header があれば返す。
   */
  get Protected(): JWSProtectedHeader | undefined {
    return this.p;
  }

  /**
   * JWS Unprotected Header があれば返す。
   */
  get Unprotected(): JWSUnprotectedHeader | undefined {
    return this.u;
  }
}
/**
 * JWS Signature によって完全性を保護されるヘッダーパラメータを含む JSON オブジェクト。
 */
type JWSProtectedHeader = Partial<JWSJOSEHeader>;

const isJWSProtectedHeader = (arg: unknown): arg is JWSProtectedHeader =>
  isPartialJWSJOSEHeader(arg);

/**
 * 完全性を保護されないヘッダーパラメータを含む JSON オブジェクト。
 */
type JWSUnprotectedHeader = Partial<JWSJOSEHeader>;

const isJWSUnprotectedHeader = (arg: unknown): arg is JWSUnprotectedHeader =>
  isPartialJWSJOSEHeader(arg);

/**
 * RFC7515#4
 * JWS において JOSE Header のプロパティは、JWS Protected Header と JWS Payload に適用される
 * デジタル署名や MAC やオプションで JWS の追加プロパティを記述する。
 */
type JWSJOSEHeader<A extends JWSAlg = JWSAlg> = {
  /**
   * RFC7515#4.1.1 Algorithm Header Parameter
   * JWS を保護するために使う暗号アルゴリズムを識別する。
   * IANA に登録済みのものだけ有効とした。
   */
  alg: A;
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

const jwsJOSEHeaderNameList = [
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
 * ２つの JWSJOSEHEader が同じか判定する
 */
function equalsJWSJOSEHeader(l?: Partial<JWSJOSEHeader>, r?: Partial<JWSJOSEHeader>): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of jwsJOSEHeaderNameList) {
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
 * 引数が JWSJOSEHeader か確認する。
 * JWS で定義されている JWSJOSEHeader パラメータをもち、 alg を持っているか確認する。
 */
const isJWSJOSEHeader = (arg: unknown): arg is JWSJOSEHeader => {
  return isPartialJWSJOSEHeader(arg) && arg.alg != null;
};

/**
 * 引数が Partial<JWSJOSEHeader> か確認する。
 * isJWSJOSEHeader は alg が値を持っているか確認するが、これでは undefined でも良いとしている。
 */
function isPartialJWSJOSEHeader(arg: unknown): arg is Partial<JWSJOSEHeader> {
  return (
    isObject<Partial<JWSJOSEHeader>>(arg) &&
    jwsJOSEHeaderNameList.every(
      (n) =>
        arg[n] == null ||
        (n === 'alg'
          ? isJWSAlg(arg[n])
          : n === 'jwk'
          ? isJWK(arg[n])
          : n === 'x5c' || n === 'crit'
          ? Array.isArray(arg[n]) && (arg[n] as unknown[]).every((m) => typeof m === 'string')
          : typeof arg[n] === 'string')
    )
  );
}
