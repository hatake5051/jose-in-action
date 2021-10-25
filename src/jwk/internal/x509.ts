// --------------------BEGIN X.509 DER praser --------------------

import { CONCAT } from '../../util';

export { X509Cert, parseX509BASE64EncodedDER, validateSelfSignedCert, isX509SPKI };

/**
 * 自己署名証明書の X.509 証明書を受け取って、有効性の検証を行う。
 * ここで行う有効性の検証は TBSCertificate.signature に書かれてあるアルゴリズムを使って、
 * TBSCertificate.subjectPublicKeyInfo の公開鍵を用いて Certificate.signatureValue
 * の検証ができるかのみを行う。
 * validity の検証など必要な様々な検証が未実装である。
 */
async function validateSelfSignedCert(crt: X509Cert): Promise<boolean> {
  // alg を識別する
  const alg = crt.sigAlg;
  if (alg !== crt.tbs.alg) {
    throw EvalError('signatureAlgorithm !== TBSCertificate.signature エラー');
  }
  // for Public-Key Cryptography Standards (PKCS) OID
  if (alg.startsWith('1.2.840.113549.1.1')) {
    let keyAlg: RsaHashedImportParams;
    const verifyAlg = 'RSASSA-PKCS1-v1_5';
    switch (alg) {
      // sha1-with-rsa-signature とか sha1WithRSAEncryption
      case '1.2.840.113549.1.1.5':
        keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' };
        break;
      // sha256WithRSAEncryption
      case '1.2.840.113549.1.1.11':
        keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
        break;
      default:
        throw EvalError(`unimplemented rsa alg(${alg})`);
    }
    const pubkey = await crypto.subtle.importKey('spki', crt.tbs.spki.raw, keyAlg, false, [
      'verify',
    ]);
    return crypto.subtle.verify(verifyAlg, pubkey, crt.sig, crt.tbs.raw);
  }
  // OID(ansi-X9-62 signatures) は ecdsa の署名アルゴリズムを識別する
  if (alg.startsWith('1.2.840.10045.4')) {
    let keyAlg: EcKeyImportParams;
    let verifyAlg: EcdsaParams;
    switch (alg) {
      // ecdsa-with-SHA256 (RFC5480)
      case '1.2.840.10045.4.3.2':
        keyAlg = { name: 'ECDSA', namedCurve: 'P-256' };
        verifyAlg = { name: 'ECDSA', hash: 'SHA-256' };
        break;
      // ecdsa-with-SHA384
      case '1.2.840.10045.4.3.3':
        keyAlg = { name: 'ECDSA', namedCurve: 'P-384' };
        verifyAlg = { name: 'ECDSA', hash: 'SHA-384' };
        break;
      // ecdsa-with-SHA512
      case '1.2.840.10045.4.3.4':
        keyAlg = { name: 'ECDSA', namedCurve: 'P-521' };
        verifyAlg = { name: 'ECDSA', hash: 'SHA-512' };
        break;
      default:
        throw EvalError(`unimplemented ec alg(${alg})`);
    }
    const pubkey = await crypto.subtle.importKey('spki', crt.tbs.spki.raw, keyAlg, false, [
      'verify',
    ]);
    return crypto.subtle.verify(verifyAlg, pubkey, crt.sig, crt.tbs.raw);
  }
  throw EvalError(`unimplemented alg(${alg})`);
}

/**
 * X509 Certificate を表現する
 * Certificate  ::=  SEQUENCE  {
 *      tbsCertificate       TBSCertificate,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signatureValue       BIT STRING  }
 */
type X509Cert = {
  tbs: X509TBSCert;
  sigAlg: X509AlgId;
  /**
   * JWS で処理できる形に変換する
   * RSA の場合はそのままでいいが、 EC は X.509 と異なるので変換する
   */
  sig: Uint8Array;
};

// X509 Algorithm Identifier は OID のみを表現することにした
// 本来は algorithm ごとに用意された parameters ももつ
type X509AlgId = string;

/**
 * X.509 Certificate を表す、BASE64 エンコードされた DER をパースする
 */
function parseX509BASE64EncodedDER(der_b64: string): X509Cert {
  return parseX509DER(BASE64_DECODE(der_b64));
}

function parseX509DER(der_raw: Uint8Array): X509Cert {
  const der = DER_DECODE(der_raw);
  if (der.class !== 'Universal' || der.pc !== 'Constructed' || der.tag !== TAG_SEQUENCE) {
    throw EvalError('X509Cert DER フォーマットを満たしていない');
  }
  const seq = derArrayFromSEQUENCE(der);
  if (seq.length !== 3) {
    throw EvalError('X509Cert DER format を満たしていない');
  }
  const tbs_der = seq[0];
  // AlgorithmIdentifier は以下の通りで、 RSA-PKCSv1.5 と ECDSA では parameter が null
  // SEQUENCE  {
  //   algorithm               OBJECT IDENTIFIER,
  //   parameters              ANY DEFINED BY algorithm OPTIONAL  }
  const alg_der = derArrayFromSEQUENCE(seq[1])[0];
  const sigAlg: X509AlgId = convertDotNotationFromOID(alg_der);
  const sig_der = seq[2];
  let sig: Uint8Array;
  switch (sigAlg) {
    // shaXXXWithRSAEncryption
    case '1.2.840.113549.1.1.5':
    case '1.2.840.113549.1.1.11':
      sig = extractBytesFromBITSTRING(sig_der);
      break;
    // ecdsa-with-SHAXXX の時は
    // Ecdsa-Sig-Value  ::=  SEQUENCE  { r INTEGER, s INTEGER }
    case '1.2.840.10045.4.3.2':
    case '1.2.840.10045.4.3.3':
    case '1.2.840.10045.4.3.4': {
      const [r, s] = derArrayFromSEQUENCE(DER_DECODE(extractBytesFromBITSTRING(sig_der)));
      // JWS などでサポートする署名値 format は r と s のバイナリ表現を単にくっつけただけのやつ
      sig = CONCAT(
        extractNonNegativeIntegerFromInteger(r),
        extractNonNegativeIntegerFromInteger(s)
      );
      break;
    }
    default:
      throw EvalError(`parseX509DER does not support this alg(${sigAlg})`);
  }
  return { tbs: parseX509TBSCert(tbs_der), sigAlg, sig };
}

/**
 * X509 To be Signed Certificate  フィールドを表現する
 * 今回、Certificate の中身まで検証はしないので（本来はするべき）
 * 署名検証に必要な tbsCertificate のバイナリ表現と、公開鍵情報を表現することにした
 */
type X509TBSCert = {
  /**
   * raw は DER エンコードされているその値を持つ
   */
  raw: Uint8Array;
  /**
   * alg は TBSCertificate.signature フィールドにある algorithmIdentifier を表す
   */
  alg: X509AlgId;
  /**
   * spki は TBSCertificate.subjectPublicKeyInfo フィールドの生の値を持つ
   */
  spki: X509SPKI<'RSA' | 'EC'>;
};

/**
 * X509 tbsCertificate の DER 表現をパースする
 *  TBSCertificate  ::=  SEQUENCE  {
 *         version         [0]  EXPLICIT Version DEFAULT v1,
 *         serialNumber         CertificateSerialNumber,
 *         signature            AlgorithmIdentifier,
 *         issuer               Name,
 *         validity             Validity,
 *         subject              Name,
 *         subjectPublicKeyInfo SubjectPublicKeyInfo,
 *         issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
 *         subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
 *         extensions      [3]  EXPLICIT Extensions OPTIONAL        -- If present, version MUST be v3        }
 */
function parseX509TBSCert(der: DER): X509TBSCert {
  // TBSCert は SEQUENCE で表される
  if (der.class !== 'Universal' || der.pc !== 'Constructed' || der.tag !== TAG_SEQUENCE) {
    throw EvalError('X509TBSCert DER フォーマットを満たしていない');
  }
  const seq = derArrayFromSEQUENCE(der);
  // Version は省略されるかもしれない (その場合は古いバージョンなのでエラーにする)
  if (seq[0].class !== 'ContentSpecific') {
    throw EvalError('X509v3 certificate ではない');
  }
  return {
    raw: der.raw,
    alg: convertDotNotationFromOID(DER_DECODE(seq[2].value)),
    spki: parseX509SPKI(seq[6]),
  };
}

/**
 * X509Cert.TbsCertificate.Subject Public Key Info を表現する
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING  }
 *
 *   AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
type X509SPKI<K extends 'RSA' | 'EC'> = {
  kty: K;
  raw: Uint8Array;
} & (K extends 'RSA'
  ? {
      n: Uint8Array;
      e: Uint8Array;
    }
  : K extends 'EC'
  ? {
      crv: string;
      x: Uint8Array;
      y: Uint8Array;
    }
  : never);

const isX509SPKI = <K extends 'RSA' | 'EC'>(arg: unknown, kty?: K): arg is X509SPKI<K> => {
  if (typeof arg !== 'object') return false;
  if (arg == null) return false;
  if ('kty' in arg) {
    const a = arg as { kty: unknown };
    if (typeof a.kty !== 'string') return false;
    if (kty !== a.kty) return false;
    switch (a.kty) {
      case 'RSA':
        return 'raw' in a && 'n' in a && 'e' in a;
      case 'EC':
        return 'raw' in a && 'x' in a && 'y' in a;
      default:
        throw TypeError(`isX509SPKI(${kty}) is not implemented`);
    }
  }
  return false;
};

function parseX509SPKI(der: DER): X509SPKI<'RSA' | 'EC'> {
  if (der.class !== 'Universal' || der.pc !== 'Constructed' || der.tag !== TAG_SEQUENCE) {
    throw EvalError('SubjectPublicKeyInfo DER フォーマットを満たしていない');
  }
  const [algID, spki] = derArrayFromSEQUENCE(der);
  const [alg, param] = derArrayFromSEQUENCE(algID);
  switch (convertDotNotationFromOID(alg)) {
    // このOID(rsaEncryption) は RSA 公開鍵を識別する (RFC3279)
    case '1.2.840.113549.1.1.1': {
      // パラメータは null である
      if (param.class !== 'Universal' || param.tag !== TAG_NULL) {
        throw EvalError('RSA公開鍵のフォーマットを満たしていない');
      }
      // spki は次のフォーマットになる (RFC3279)
      // RSAPublicKey ::= SEQUENCE {
      //   modulus            INTEGER,    -- n
      //   publicExponent     INTEGER  }  -- e
      const [n, e] = derArrayFromSEQUENCE(DER_DECODE(extractBytesFromBITSTRING(spki)));
      return {
        kty: 'RSA',
        raw: der.raw,
        n: extractNonNegativeIntegerFromInteger(n),
        e: extractNonNegativeIntegerFromInteger(e),
      };
    }
    // このOID(id-ecPublicKey) は EC 公開鍵を識別する (RFC5480)
    case '1.2.840.10045.2.1': {
      // namedCurve 以外はPKIX では使われないのでスルー (RFC5480)
      // EcpkParameters ::= CHOICE {
      //  namedCurve    OBJECT IDENTIFIER,
      //  implicitCurve  NULL,
      //  specifiedCurve SpecifiedECDomain }
      if (param.class !== 'Universal' || param.tag !== TAG_OBJECTIDENTIFIER) {
        throw EvalError('EC公開鍵のパラメータは OID 指定のみ実装する');
      }
      // 圧縮されていない前提で考えている。
      // 圧縮されていない場合 spki には  0x04 || x || y で公開鍵がエンコードされている.
      const xy = extractBytesFromBITSTRING(spki);
      const x = xy.slice(1, (xy.length - 1) / 2 + 1);
      const y = xy.slice((xy.length - 1) / 2 + 1);
      switch (convertDotNotationFromOID(param)) {
        // secp256r1 つまり P-256 カーブを意味する
        case '1.2.840.10045.3.1.7':
          return { kty: 'EC', raw: der.raw, crv: 'P-256', x, y };
        // secp384r1 つまり P-384 カーブを意味する
        case '1.3.132.0.34':
          return { kty: 'EC', raw: der.raw, crv: 'P-384', x, y };
        default:
          throw EvalError('SPKI parser for ec unimplmented');
      }
    }
    default:
      throw EvalError('SPKI parser Unimplemented!');
  }
}

// DER パーサを実装する。
// 参考文献: https://blog.engelke.com/2014/10/17/parsing-ber-and-der-encoded-asn-1-objects/
// 参考文献: http://websites.umich.edu/~x509/ssleay/layman.html

type Class = 'Universal' | 'Application' | 'ContentSpecific' | 'Private';

const TAG_INTEGER = 2;
const TAG_BITSTRING = 3;
const TAG_NULL = 5;
const TAG_OBJECTIDENTIFIER = 6;
const TAG_SEQUENCE = 16;

/**
 * Primitive な DER で表現された Integer からバイナリ表現の非負整数を取り出す。
 * DER encoding では整数は符号付きなので非負整数は負の数と間違われないために先頭に 0x00 がついている。
 * 非負整数のみを扱うと分かっていれば別に先頭のオクテットはいらないので消して取り出す。
 */
function extractNonNegativeIntegerFromInteger(der: DER): Uint8Array {
  if (der.class !== 'Universal' || der.pc !== 'Primitive' || der.tag !== TAG_INTEGER) {
    throw EvalError('INTEGER ではない DER format を扱おうとしている');
  }
  if (der.value[0] === 0x00) {
    return der.value.slice(1);
  }
  return der.value;
}

/**
 * Primitive な DER で表現された BITString からバイナリを取り出す
 */
function extractBytesFromBITSTRING(der: DER): Uint8Array {
  if (der.class !== 'Universal' || der.pc !== 'Primitive' || der.tag !== TAG_BITSTRING) {
    throw EvalError('BITSTRING ではない DER format を扱おうとしている');
  }
  const v = der.value;
  // 先頭のオクテットはbit-length を８の倍数にするためにケツに追加した 0-padding の数を表現する
  if (v[0] === 0x00) return v.slice(1);
  // 先頭のオクテットが０でないときは、その数だけ padding 処理を行う
  const contentWithPadEnd = v.slice(1).reduce((sum, i) => sum + i.toString(2).padStart(8, '0'), '');
  const content = contentWithPadEnd.slice(0, contentWithPadEnd.length - v[0]);
  const contentWithPadStart = '0'.repeat(v[0]) + content;
  const ans = new Uint8Array(contentWithPadStart.length / 8);
  for (let i = 0; i < ans.length; i++) {
    ans[i] = parseInt(contentWithPadStart.substr(i * 8, 8), 2);
  }
  return ans;
}

/**
 * OID の DER 表現から Object Identifier のドット表記に変換する
 */
function convertDotNotationFromOID(der: DER): string {
  if (der.class !== 'Universal' || der.pc !== 'Primitive' || der.tag !== TAG_OBJECTIDENTIFIER) {
    throw EvalError('OID ではない DER format を扱おうとしている');
  }
  const v = der.value;
  const ans = [];
  // the first octet has 40 * value1 + value2
  ans.push(Math.floor(v[0] / 40));
  ans.push(v[0] % 40);
  let i = 1;
  while (i < v.length) {
    if (v[i] < 0x80) {
      ans.push(v[i]);
      i++;
      continue;
    }
    let tmp = 0;
    do {
      tmp = tmp * 128 + (v[i] - 0x80) * 128;
      i++;
    } while (v[i] > 0x80);
    tmp += v[i];
    ans.push(tmp);
    i++;
  }
  return ans.join('.');
}

/**
 * Constructed な DER で表現された SEQUENCE を JSのオブジェクトである Array<DER> に変換する
 */
function derArrayFromSEQUENCE(der: DER): Array<DER> {
  if (der.class !== 'Universal' || der.pc !== 'Constructed' || der.tag !== TAG_SEQUENCE) {
    throw EvalError('SEQUENCE ではない DER format を扱おうとしている');
  }
  const v = der.value;
  const ans = [];
  let start = 0;
  while (start < v.length) {
    const c = DER_DECODE(v.slice(start));
    ans.push(c);
    start += c.entireLen;
  }
  return ans;
}

/**
 * DER はバイナリの DER をある程度解釈して Type, Length, Value の組にしたものを表す。
 * DER は Type Field || Length Field || Value Field の連結で表現されている。
 * Type が Value の型を表現する。 型を表現するために Tag で型が識別できる。 Tag は Class で分類され、 Universal な Class
 * のものは ASN.1 にて定義されているが、 Private とかは当事者間で合意して使うものである。
 * また、 Tag には基本型と構造型に分類でき、構造型は他の DER 表現のコンテナとして使われる
 * Length は Value の長さを表現する。
 * Value は値を表現して、Typeによって何が入っているか定まる。
 */
type DER = {
  /**
   * Tag のクラスを表す。 Universal なクラスのタグは ASN.1 にて定義されている
   */
  class: Class;
  /**
   * BITSTRING のような基本型を Primiteve、 SEQUENCE のような構造型を Constructed で区別する
   */
  pc: 'Primitive' | 'Constructed';
  /**
   * Tag はデータ型を表現する。Universal なクラスのタグだと 3: SEQUENCE, 16: BITSTRING である。
   */
  tag: number;
  /**
   * Value のオクテット長を表す。
   */
  len: number;
  /**
   * この DER 全体のオクテット長を表す
   */
  entireLen: number;
  /**
   * 値をバイナリとして表す。Tagごとのパーサに解釈は任せる。
   */
  value: Uint8Array;
  /**
   * この DER 自体のバイナリを表す。
   */
  raw: Uint8Array;
};

/**
 * バイナリエンコードされている DER を何の値を表現するかまでパースする。
 */
function DER_DECODE(ber: Uint8Array): DER {
  const { tag, typeFieldLen } = parseTagNum(ber);
  const { len, lengthFieldLen } = parseLength(ber.slice(typeFieldLen));
  const value = ber.slice(typeFieldLen + lengthFieldLen, typeFieldLen + lengthFieldLen + len);
  return {
    class: parseClass(ber),
    pc: parsePC(ber),
    tag,
    len,
    entireLen: typeFieldLen + lengthFieldLen + len,
    value,
    raw: ber.slice(0, typeFieldLen + lengthFieldLen + len),
  };
}

/**
 * TypeField の最初の２ビットがクラスを表現している
 */
function parseClass(typeField: Uint8Array): Class {
  const cls = (typeField[0] & 0xc0) >> 6;
  switch (cls) {
    case 0:
      return 'Universal';
    case 1:
      return 'Application';
    case 2:
      return 'ContentSpecific';
    case 3:
      return 'Private';
    default:
      throw EvalError('クラスは 00 ~ 11 の範囲のみ');
  }
}

/**
 * TypeField の3ビット目が基本型か構造型かを表現している
 */
function parsePC(typeField: Uint8Array): 'Primitive' | 'Constructed' {
  const ps = (typeField[0] & 0x20) >> 5;
  switch (ps) {
    case 0:
      return 'Primitive';
    case 1:
      return 'Constructed';
    default:
      throw EvalError('P/C は 0 か 1 のいずれか');
  }
}

/**
 * TypeField の4ビット目以降が Tag番号を表現している。
 * tag number < 31 なら TypeField は１オクテットだが、
 * 超えるようならいい感じに後ろのオクテットも使って表現する。
 * そのため Tag 番号をパースすることで初めて TypeField のオクテット長が決まる。
 */
function parseTagNum(typeField: Uint8Array): {
  tag: number;
  typeFieldLen: number;
} {
  // Type Field の下位５ビットが tag を表現する.
  let tag = typeField[0] & 0x1f;
  // 全てが１でないなら、それは Tag number を表現している。
  // 全て１の時は後続が tag を表現している。
  if (tag < 0x1f) return { tag, typeFieldLen: 1 };
  tag = 0;
  let i = 0;
  do {
    i++;
    // 後続オクテットの下位7bit が tag number を表現
    // 上位１bit が一である限り後続も tag number を表現しているので、
    // それらを連結したものが tag number
    const t = typeField[i] & 0x7f;
    tag = (tag << 7) + t;
  } while ((typeField[i] & 0x80) >> 7 !== 0);
  return { tag, typeFieldLen: 1 + i };
}

/**
 * LengthField を解釈して Value のオクテット長を求める。
 * Value の長さが 127 以下なら LengthField は 1 オクテットで表現されるが、
 * 超えるようならいい感じに後ろのオクテットも使って表現する。
 * そのため Length をパースすることで初めて Length Field のオクテット長が決まる
 */
function parseLength(lengthField: Uint8Array): {
  len: number;
  lengthFieldLen: number;
} {
  if (lengthField[0] < 0x80) {
    return { len: lengthField[0] & 0x7f, lengthFieldLen: 1 };
  }
  // Length Field の先頭１ビットが１の時は、長さが 128 を超えているということ
  const additionalLengthFieldLen = lengthField[0] & 0x7f;
  let len = 0;
  for (let i = 0; i < additionalLengthFieldLen; i++) {
    len = (len << 8) + lengthField[1 + i];
  }
  return { len, lengthFieldLen: 1 + additionalLengthFieldLen };
}

function BASE64_DECODE(STRING: string) {
  const b_str = window.atob(STRING);
  // バイナリ文字列を Uint8Array に変換する
  const b = new Uint8Array(b_str.length);
  for (let i = 0; i < b_str.length; i++) {
    b[i] = b_str.charCodeAt(i);
  }
  return b;
}

// --------------------END X.509 DER parser --------------------
