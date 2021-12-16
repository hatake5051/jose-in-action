import { Alg, EncAlg, isAlg, isEncAlg } from 'iana/alg';
import { JOSEHeader } from 'iana/header';
import { equalsJWK, isJWK, JWK } from 'jwk';
import { isObject } from 'utility';

/**
 * JWECEK は Content Encryption Key を表す.
 * ランダムに生成か、鍵合意に基づく値か、事前共有鍵に基づく値のいずれか
 */
export type JWECEK = Uint8Array & { _brand: 'JWECEK' };

/**
 * JWEEncryptedKey は CEK を暗号化した値を表す
 * CEK を暗号化しない場合(DirectKeyEncrytion or DirectKeyAgreement) は empty octet sequence である。
 */
export type JWEEncryptedKey = Uint8Array & { _brand: 'JWEEncryptedKey' };

/**
 * JWECiphertext はメッセージを暗号化した結果を表現する.
 */
export type JWECiphertext = Uint8Array & { _brand: 'JWECiphertext' };

/**
 * JWETag は認証付き暗号の結果の Authentication Tag を表現する.
 */
export type JWETag = Uint8Array & { _brand: 'JWETag' };

/**
 * JWEAAD は the authenticated encryption operatoion で integrity が保護される Additional Authenticated Data を表す.
 * Compact Serialization では用いることができない.
 */
export type JWEAAD = Uint8Array & { _brand: 'JWEAAD' };

/**
 * JWEIV は Initialization Vector を表す.
 * Content を暗号化するときに使う.
 * IV を使わないアルゴリズムでは the empty octed sequence である。
 */
export type JWEIV = Uint8Array & { _brand: 'JWEIV' };

export type JWEProtectedHeader = JOSEHeader<'JWE'> & { _brand: 'JWEProtectedHeader' };
export type JWESharedUnprotectedHeader = JOSEHeader<'JWE'> & {
  _brand: 'JWESharedUnprotectedHeader';
};
export type JWEPerRecipientUnprotectedHeader = JOSEHeader<'JWE'> & {
  _brand: 'JWEPerRecipientUnprotectedHeader';
};

export type JWEJOSEHeader = {
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

export const isJWEJOSEHeader = (arg: unknown): arg is JWEJOSEHeader =>
  isPartialJWEJOSEHeader(arg) && arg.alg != null && arg.enc != null;

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

export const isPartialJWEJOSEHeader = (arg: unknown): arg is Partial<JWEJOSEHeader> =>
  isObject<Partial<JWEJOSEHeader>>(arg) &&
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

export function equalsJWEJOSEHeader(
  l?: Partial<JWEJOSEHeader>,
  r?: Partial<JWEJOSEHeader>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of JWEJOSEHeaderParamNames) {
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

export type JWECompactSerialization = string;

export type JWEJSONSerialization = {
  protected?: string;
  unprotected?: JWESharedUnprotectedHeader;
  iv?: string;
  aad?: string;
  ciphertext: string;
  tag?: string;
  recipients: {
    header?: JWEPerRecipientUnprotectedHeader;
    encrypted_key?: string;
  }[];
};

export type JWEFlattenedJSONSerialization = {
  protected?: string;
  unprotected?: JWESharedUnprotectedHeader;
  header?: JWEPerRecipientUnprotectedHeader;
  encrypted_key?: string;
  iv?: string;
  aad?: string;
  ciphertext: string;
  tag?: string;
};
