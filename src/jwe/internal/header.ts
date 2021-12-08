import { KeyMgmtMode } from 'jwe/ineterface';
import { equalsJWK, isJWK, JWK } from 'jwk';
import { isObject } from 'utility';
import {
  AlgSpecificJOSEHeader,
  isAlgSpecificJOSEHeader,
  isJWEAlg,
  isJWEDEAlg,
  isJWEDKAAlg,
  isJWEEnc,
  isJWEKAKWAlg,
  isJWEKEAlg,
  isJWEKWAlg,
  JWEAlg,
  JWEAlgFromKeyMgmtMode,
  JWEEnc,
} from './di';

export {
  JWEHeader,
  JWEJOSEHeader,
  JWEProtectedHeader,
  isJWEProtectedHeader,
  equalsJWEProtectedHeader,
  JWESharedUnprotectedHeader,
  isJWESharedUnprotectedHeader,
  equalsJWESharedUnprotectedHeader,
  JWEPerRecipientUnprotectedHeader,
  isJWEPerRecipientUnprotectedHeader,
  equalsJWEPerRecipientUnprotectedHeader,
};

class JWEHeader<A extends JWEAlg = JWEAlg, E extends JWEEnc = JWEEnc> {
  private p?: JWEProtectedHeader<A, E>;
  private su?: JWESharedUnprotectedHeader<A, E>;
  private ru?: JWEPerRecipientUnprotectedHeader<A, E>;
  private h: JWEJOSEHeader<A, E> & AlgSpecificJOSEHeader<A>;

  constructor(
    p?: JWEProtectedHeader<A, E>,
    su?: JWESharedUnprotectedHeader<A, E>,
    ru?: JWEPerRecipientUnprotectedHeader<A, E>
  ) {
    const h = { ...p, ...su, ...ru };
    if (!(isJWEJOSEHeader(h) && isAlgSpecificJOSEHeader<typeof h.alg>(h)))
      throw new TypeError(`JOSE Header for JWE に必要なパラメータが不足している`);
    this.p = p;
    this.su = su;
    this.ru = ru;
    this.h = h;
  }

  get Alg(): A {
    return this.h.alg;
  }

  get Enc(): E {
    return this.h.enc;
  }

  get JOSEHeader(): JWEJOSEHeader<A, E> & AlgSpecificJOSEHeader<A> {
    return this.h;
  }

  get Protected(): JWEProtectedHeader | undefined {
    return this.p;
  }

  get SharedUnprotected(): JWESharedUnprotectedHeader | undefined {
    return this.su;
  }

  get PerRecipientUnprotected(): JWEPerRecipientUnprotectedHeader | undefined {
    return this.ru;
  }

  cast<K extends KeyMgmtMode>(mode: K): this is JWEHeader<JWEAlgFromKeyMgmtMode<K>> {
    switch (mode) {
      case 'KE':
        return isJWEKEAlg(this.Alg);
      case 'KW':
        return isJWEKWAlg(this.Alg);
      case 'DKA':
        return isJWEDKAAlg(this.Alg);
      case 'KAKW':
        return isJWEKAKWAlg(this.Alg);
      case 'DE':
        return isJWEDEAlg(this.Alg);
      default:
        throw new EvalError(`Key Management mode に ${mode} はない`);
    }
  }
}

type JWESharedUnprotectedHeader<A extends JWEAlg = JWEAlg, E extends JWEEnc = JWEEnc> = Partial<
  JWEJOSEHeader<A, E> & AlgSpecificJOSEHeader<A>
>;

const isJWESharedUnprotectedHeader = (arg: unknown): arg is JWESharedUnprotectedHeader =>
  isPartialJWEJOSEHeader(arg);

const equalsJWESharedUnprotectedHeader = (
  l?: JWESharedUnprotectedHeader,
  r?: JWESharedUnprotectedHeader
) => equalsPartialJWEJOSEHeader(l, r);

type JWEPerRecipientUnprotectedHeader<
  A extends JWEAlg = JWEAlg,
  E extends JWEEnc = JWEEnc
> = Partial<JWEJOSEHeader<A, E> & AlgSpecificJOSEHeader<A>>;

const isJWEPerRecipientUnprotectedHeader = (
  arg: unknown
): arg is JWEPerRecipientUnprotectedHeader => isPartialJWEJOSEHeader(arg);

const equalsJWEPerRecipientUnprotectedHeader = (
  l?: JWEPerRecipientUnprotectedHeader,
  r?: JWEPerRecipientUnprotectedHeader
) => equalsPartialJWEJOSEHeader(l, r);

type JWEProtectedHeader<A extends JWEAlg = JWEAlg, E extends JWEEnc = JWEEnc> = Partial<
  JWEJOSEHeader<A, E> & AlgSpecificJOSEHeader<A>
>;

const isJWEProtectedHeader = (arg: unknown): arg is JWEProtectedHeader =>
  isPartialJWEJOSEHeader(arg);

const equalsJWEProtectedHeader = (l?: JWEProtectedHeader, r?: JWEProtectedHeader) =>
  equalsPartialJWEJOSEHeader(l, r);

type JWEJOSEHeader<A extends JWEAlg = JWEAlg, E extends JWEEnc = JWEEnc> = {
  /**
   * RFC7516#4.1.1 Algorithm Header Parameter
   * CEK の暗号化もしくは CEK を決定するために使用される。
   */
  alg: A;
  /**
   * RFC7516#4.1.2 Encryption Algorithm Header Parameter
   * 平文を暗号化するためのコンテンツ暗号化アルゴリズムを識別する。
   */
  enc: E;
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

const isJWEJOSEHeader = (arg: unknown): arg is JWEJOSEHeader =>
  isPartialJWEJOSEHeader(arg) && arg.alg != null && arg.enc != null;

const jweJOSEHeaderNameList = [
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

const isPartialJWEJOSEHeader = (arg: unknown): arg is Partial<JWEJOSEHeader> =>
  isObject<Partial<JWEJOSEHeader>>(arg) &&
  jweJOSEHeaderNameList.every(
    (n) =>
      arg[n] == null ||
      (n === 'alg'
        ? isJWEAlg(arg[n])
        : n === 'enc'
        ? isJWEEnc(arg[n])
        : n === 'jwk'
        ? isJWK(arg[n])
        : n === 'x5c' || n === 'crit'
        ? Array.isArray(arg[n]) && (arg[n] as unknown[]).every((m) => typeof m === 'string')
        : typeof arg[n] === 'string')
  );

function equalsPartialJWEJOSEHeader(
  l?: Partial<JWEJOSEHeader>,
  r?: Partial<JWEJOSEHeader>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of jweJOSEHeaderNameList) {
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
