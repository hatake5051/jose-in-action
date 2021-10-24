// --------------------BEGIN X.509 DER praser --------------------

export { X509Cert, parseX509BASE64EncodedDER, validateSelfSignedCert };

type Class = 'Universal' | 'Application' | 'ContentSpecific' | 'Private';
const TAG_SEQUENCE = 16;
const TAG_BITSTRING = 3;
const TAG_OBJECTIDENTIFIER = 6;

/**
 * X509 Certificate を表現する
 */
type X509Cert = {
  tbs: X509TBSCert;
  /**
   * なぜ signature Algorithm field が存在するのかわからなかった。
   * TBSCertificate.signature の方と一致すべきならそっちだけでいいじゃん。
   */
  sigAlg: X509AlgId;
  sig: Uint8Array;
};

/**
 * X.509 Certificate を表す、BASE64 エンコードされた DER をパースする
 */
function parseX509BASE64EncodedDER(der_b64: string): X509Cert {
  return parseX509DER(BASE64_DECODE(der_b64));
}

async function validateSelfSignedCert(crt: X509Cert): Promise<boolean> {
  // alg を識別する
  const alg = crt.sigAlg.join('.');
  if (alg !== crt.tbs.alg.join('.')) {
    throw EvalError('signatureAlgorithm !== TBSCertificate.signature エラー');
  }
  // for Public-Key Cryptography Standards (PKCS) OID
  if (alg.startsWith('1.2.840.113549.1.1')) {
    let keyAlg;
    let verifyAlg;
    if (alg === '1.2.840.113549.1.1.5') {
      // sha1-with-rsa-signature とか sha1WithRSAEncryption
      keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' };
      verifyAlg = 'RSASSA-PKCS1-v1_5';
    } else if (alg === '1.2.840.113549.1.1.11') {
      // sha256WithRSAEncryption
      keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      verifyAlg = 'RSASSA-PKCS1-v1_5';
    } else {
      throw EvalError(`unimplemented rsa alg(${alg})`);
    }
    const pubkey = await crypto.subtle.importKey('spki', crt.tbs.spki, keyAlg, false, ['verify']);
    return crypto.subtle.verify(verifyAlg, pubkey, crt.sig, crt.tbs.raw);
  }
  throw EvalError(`unimplemented alg(${alg})`);
}

// X509 Algorithm Identifier は OID のみを表現することにした
// 本来は algorithm ごとに用意された parameters ももつ
type X509AlgId = number[];

function parseX509DER(der_raw: Uint8Array): X509Cert {
  const der = DER_DECODE(der_raw);
  if (der.class !== 'Universal' || der.pc !== 'Constructed' || der.tag !== TAG_SEQUENCE) {
    throw EvalError('X509Cert DER フォーマットを満たしていない');
  }
  const tbs_der = DER_DECODE(der.value);

  const sigalg_der = DER_DECODE(der.value.slice(tbs_der.entireLen));
  const sigAlg: X509AlgId = convertDotNotationFromOID(DER_DECODE(sigalg_der.value));

  const sig_der = DER_DECODE(der.value.slice(tbs_der.entireLen + sigalg_der.entireLen));

  return {
    tbs: parseX509TBSCert(tbs_der),
    sigAlg,
    sig: extractBytesFromBITSTRING(sig_der),
  };
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
  spki: Uint8Array;
};

/**
 * X509 tbsCertificate の DER 表現をパースする
 */
function parseX509TBSCert(der: DER): X509TBSCert {
  // TBSCert は SEQUENCE で表される
  if (der.class !== 'Universal' || der.pc !== 'Constructed' || der.tag !== TAG_SEQUENCE) {
    throw EvalError('X509TBSCert DER フォーマットを満たしていない');
  }
  // 一番初めは Version
  const version = DER_DECODE(der.value);
  let start = version.entireLen;
  // 次は Serial Number
  const serialNumber = DER_DECODE(der.value.slice(start));
  start += serialNumber.entireLen;
  const signature = DER_DECODE(der.value.slice(start));
  start += signature.entireLen;
  const issuer = DER_DECODE(der.value.slice(start));
  start += issuer.entireLen;
  const validity = DER_DECODE(der.value.slice(start));
  start += validity.entireLen;
  const subject = DER_DECODE(der.value.slice(start));
  start += subject.entireLen;
  const subjectPublicKeyInformation = DER_DECODE(der.value.slice(start));
  return {
    raw: der.raw,
    alg: convertDotNotationFromOID(DER_DECODE(signature.value)),
    spki: subjectPublicKeyInformation.raw,
  };
}

// ref: http://websites.umich.edu/~x509/ssleay/layman.html

/**
 * DER で表現された BITString からバイナリを取り出す
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
 * OID の DER 表現から Object Identifier のドット表記をパースする。
 */
function convertDotNotationFromOID(der: DER): number[] {
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
