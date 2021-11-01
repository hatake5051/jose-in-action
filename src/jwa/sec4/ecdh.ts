import { Enc } from 'iana';
import { JWECEK, JWEEncryptedKey } from 'jwe';
import { DirectAgreementer, KeyAgreementerWithKeyWrapping } from 'jwe/internal/keymgmt';
import { JWK } from 'jwk';
import { ASCII, BASE64URL, BASE64URL_DECODE, CONCAT } from 'utility';
import { AKWKeyWrapper } from './aeskw';

export {
  ECDHAlg,
  isECDHAlg,
  ECDH_ESAlg,
  isECDH_ESAlg,
  ECDH_ESKWAlg,
  isECDH_ESKWAlg,
  JWEECDHHeaderParams,
  ECDHDirectAgreementer,
  ECDHKeyAgreementerWithKeyWrapping,
};

const ECDHDirectAgreementer: DirectAgreementer<ECDH_ESAlg> = {
  partyU: async (
    h: Pick<JWEECDHHeaderParams, 'enc' | 'alg' | 'apu' | 'apv'>,
    key: JWK<'EC', 'Pub'>,
    eprivk: JWK<'EC', 'Priv'>
  ): Promise<JWECEK> => {
    return agree(h, key, eprivk);
  },
  partyV: async (h: JWEECDHHeaderParams, key: JWK<'EC', 'Priv'>): Promise<JWECEK> => {
    return agree(h, h.epk, key);
  },
};

const ECDHKeyAgreementerWithKeyWrapping: KeyAgreementerWithKeyWrapping<ECDH_ESKWAlg> = {
  wrap,
  unwrap,
};

/**
 * RFC7518#4.6 Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
 * ECDH 鍵合意アルゴリズムを列挙する。
 */
type ECDHAlg = ECDH_ESAlg | ECDH_ESKWAlg;
const isECDHAlg = (arg: unknown): arg is ECDHAlg => isECDH_ESAlg(arg) || isECDH_ESKWAlg(arg);

/**
 * "enc" アルゴリズムのための Content Encryption Key として直接、鍵合意結果を使うアルゴリズムを列挙。
 * これらはアルゴリズムは鍵管理のうち、 Direct Key Agreement mode である。
 */
type ECDH_ESAlg = 'ECDH-ES';
const isECDH_ESAlg = (arg: unknown): arg is ECDH_ESAlg =>
  typeof arg === 'string' && arg === 'ECDH-ES';

/**
 * "enc" アルゴリズムのための Content Encryption Key を AES Key wrapping するときの対称鍵として
 * 鍵合意結果を使うアルゴリズムを列挙。
 * これらはアルゴリズムは鍵管理のうち、 Key Agreement with Key Wrapping mode である。
 */
type ECDH_ESKWAlg = typeof ecdhEsKwAlgList[number];
const isECDH_ESKWAlg = (arg: unknown): arg is ECDH_ESKWAlg =>
  typeof arg === 'string' && ecdhEsKwAlgList.some((a) => a === arg);
const ecdhEsKwAlgList = ['ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'] as const;

/**
 * RFC7518#4.6.1 Header Parameters Used for ECDH Key Agreement
 * ECDH 鍵合意アルゴリズムのためのヘッダパラメータに、必須の alg と enc を加えたもの
 */
type JWEECDHHeaderParams = {
  alg: ECDHAlg;
  enc: Enc;
  /**
   * RFC8518#4.6.1.1 Ephemeral Public Key Header Parameter
   * 鍵合意アルゴリズム使用される、 originator が作成した公開鍵であり、 JWK で表現。
   * 鍵を表すために必要な最小限の JWK パラメータのみを含むべき (SHOULD)
   */
  epk: JWK<'EC', 'Pub'>;
  // agreement PartyUinfo (the producer に関する情報)
  /**
   * RFC8518#4.6.1.2 Agreement PartyUInfo Header Parameter
   * the producer に関係する情報を含む、 BASE64URL-encoded された文字列。
   * ephemeral key pair を作る側。
   */
  apu?: string;
  /**
   * RFC8518#4.6.1.3 Agreement PartyVInfo Header Parameter
   * the recipient に関係する情報を含む、 BASE64URL-encoded された文字列。
   * static public key を渡す側。
   */
  apv?: string;
};

/**
 * RFC7518#4.6.2 に基づいて鍵合意を行う。
 * Party U の場合は generated Ephemeral Private Key と Static Public Key for Party V を使って計算する。
 * Party V の場合は Ephemeral Public Key in Header と Own Private Key を使って計算する。
 */
async function agree(
  h: Pick<JWEECDHHeaderParams, 'enc' | 'alg' | 'apu' | 'apv'>,
  pub: JWK<'EC', 'Pub'>,
  priv: JWK<'EC', 'Priv'>
) {
  // ECDH は CryptoAPI 関数で行うので CryptoAPI 用の鍵に変換する
  const privKey = await window.crypto.subtle.importKey(
    'jwk',
    priv,
    { name: 'ECDH', namedCurve: priv.crv },
    true,
    ['deriveBits']
  );
  const pubKey = await window.crypto.subtle.importKey(
    'jwk',
    pub,
    { name: 'ECDH', namedCurve: pub.crv },
    true,
    []
  );
  // ECDH algorithm を用いて確立された shared secret Z
  const Z = new Uint8Array(
    await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: pubKey },
      privKey,
      // null でもいいはずなんだけどなあ c.f. https://w3c.github.io/webcrypto/#ecdh-operations
      // 結果のビット長は基本的に Crv の値と同じだけど P-521 だけは 66 bytes なので。
      pub.crv === 'P-521' ? 528 : parseInt(pub.crv.slice(2))
    )
  );
  // Concat KDF を行い、鍵を導出する
  const keydatalen = genkeydatalen(h.alg, h.enc);
  const OtherInfo = genOtherInfo(h, keydatalen);
  const keyAgreementResult = ConcatKDF(Z, { keydatalen, OtherInfo });
  return keyAgreementResult;
}

/**
 * RFC7518#4.6.2 に基づいて鍵合意を行い、行った結果をラッピング用の鍵として AES KW を使って CEK をラッピングする。
 */
async function wrap(
  h: Pick<JWEECDHHeaderParams, 'enc' | 'alg' | 'apu' | 'apv'>,
  key: JWK<'EC', 'Pub'>,
  eprivk: JWK<'EC', 'Priv'>,
  cek: JWECEK
): Promise<JWEEncryptedKey> {
  const keyAgreementResult = await agree(h, key, eprivk);
  return AKWKeyWrapper.wrap({ kty: 'oct', k: BASE64URL(keyAgreementResult) }, cek);
}

/**
 * RFC7518#4.6.2 に基づいて鍵合意を行い、行った結果をアンラッピング用の鍵として AES KW を使って EK をアンラップする。
 */
async function unwrap(
  h: JWEECDHHeaderParams,
  key: JWK<'EC', 'Priv'>,
  ek: JWEEncryptedKey
): Promise<JWECEK> {
  const keyAgreementResult = await agree(h, h.epk, key);
  return AKWKeyWrapper.unwrap({ kty: 'oct', k: BASE64URL(keyAgreementResult) }, ek);
}

/**
 * NIST SP 800-56A2#5.8.1.1 に基づいて The Single Step KDF を実装する。
 * Z が the shared secret を表すバイト列で、 keydatalen が導出される keying material のビット長。
 * OtherInfo が文脈依存のデータを表すバイト列
 */
async function ConcatKDF(
  Z: Uint8Array,
  OtherInput: { keydatalen: number; OtherInfo: Uint8Array }
): Promise<Uint8Array> {
  const { keydatalen, OtherInfo } = OtherInput;
  // Implementation-Dependent Parameters
  // RFC7518 で、 hash は SHA-256 を使う
  const hashlen = 256;
  const H = async (data: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await window.crypto.subtle.digest('SHA-256', data));
  // Process
  // Step1
  const reps = Math.ceil(keydatalen / hashlen);
  // Step2 は keydatalen が短いのが明らかなのでスキップ
  // Step3 Counter の初期化
  let counter = intToOctets(1, 4);
  let DerivedKeyingMaterial = new Uint8Array();
  // Step4 も超えなさそうなのでスキップ
  for (let i = 1; i <= reps; i++) {
    counter = intToOctets(i, 4);
    const Ki = await H(CONCAT(CONCAT(counter, Z), OtherInfo));
    DerivedKeyingMaterial = CONCAT(DerivedKeyingMaterial, Ki);
  }
  return DerivedKeyingMaterial.slice(0, keydatalen / 8);
}

/**
 * NIST.SP.800-56Ar2#5.8.1.1
 * keydatalen は導出される the secret keying material のビット長を示す。
 * ECDHAlg に応じて、 Concat KDF で使用する keydatalen parameter を決める。
 * ECDH-ES の場合は enc algorithm identifier の鍵長に依存するので、引数でそれも渡している。
 */
function genkeydatalen(alg: ECDHAlg, enc: Enc): number {
  switch (alg) {
    case 'ECDH-ES':
      switch (enc) {
        case 'A128CBC-HS256':
          return 32 * 8;
        case 'A192CBC-HS384':
          return 48 * 8;
        case 'A256CBC-HS512':
          return 64 * 8;
        case 'A128GCM':
          return 128;
        case 'A192GCM':
          return 192;
        case 'A256GCM':
          return 256;
      }
      break;
    case 'ECDH-ES+A128KW':
      return 128;
    case 'ECDH-ES+A192KW':
      return 192;
    case 'ECDH-ES+A256KW':
      return 256;
  }
}

/**
 * NIST.SP.800-56Ar2#5.8.1.2 OtherInfo
 * 導出されたキーマテリアルが the key-agreement transaction の文脈に適切に「バインド」されていることを保証するために使う。(should)
 * 例えば、OtherInfo のそれぞれの値は DataLen || Data の形式で表現されるべき(shall)。
 * Data は可変長の文字列で、DataLen は固定長のビックエンディアンのデータオクテット長表現。
 */
function genOtherInfo(
  h: Pick<JWEECDHHeaderParams, 'enc' | 'alg' | 'apu' | 'apv'>,
  keydatalen: number
): Uint8Array {
  /**
   * AlgorithmID: the derived keying material をパースする方法と the derived secret keying を使うであろうアルゴリズムを示す。
   * RFC7518 において、Data は ECDH-ES の場合は enc アルゴリズム識別子であり、それ以外は alg アルゴリズム識別子である。
   * DataLen は Data のオクテット長を示す 4bytes の非負整数（オクテット表現）。
   */
  const AlgorithmID = representOtherInfo(ASCII(isECDH_ESAlg(h.alg) ? h.enc : h.alg), 4);

  /**
   * PartyUinfo: party U (Ephemeral Key Pair を作る側) に関するパブリックな情報を含める。
   * RFC7518 において、Data は Header.apu の値を BASE64url decode した値である。
   * apu がなければ、Data は空のオクテット列で、 datalen は 0になる。
   */
  const PartyUInfo = representOtherInfo(h.apu ? BASE64URL_DECODE(h.apu) : new Uint8Array(), 4);
  /**
   * PartyVInfo: party V (static pub を提供する側) に関するパブリックな情報を含める。
   * PartyUinfo と同じフォーマットだが、使用するパラメータは Header.apv
   */
  const PartyVInfo = representOtherInfo(h.apv ? BASE64URL_DECODE(h.apv) : new Uint8Array(), 4);
  /**
   * SuppPubInfo: 互いに既知の public information を持つ。(例えば keydatalen)
   * RFC7518 では keydatalen を 32bit でビックエンディアン表現した整数
   */
  const SuppPubInfo = intToOctets(keydatalen, 4);
  /**
   * SuppPrivInfo: 互いに既知の private information を持つ。(例えば、別チャネルで伝えた共有鍵)
   * RFC7518 では空オクテット列。
   */
  const SuppPrivInfo = new Uint8Array();
  /**
   * NIST.SP.800-56Ar2#5.8.1.2.1 The Concatnation Format for OtherInfo
   * に従って OtherInfo を表現する。
   */
  const OtherInfo = CONCAT(
    AlgorithmID,
    CONCAT(PartyUInfo, CONCAT(PartyVInfo, CONCAT(SuppPubInfo, SuppPrivInfo)))
  );
  return OtherInfo;
}

/**
 * OtherInfo の各値を Datalen || Data の形にする。
 */
function representOtherInfo(data: Uint8Array, datalenlen: number): Uint8Array {
  const datalen = intToOctets(data.length, datalenlen);
  return CONCAT(datalen, data);
}

/**
 * 非負整数を xLen の長さのオクテットで表現する。
 * 表現はビックエンディアン。
 */
function intToOctets(x: number, xLen: number): Uint8Array {
  let xStr = x.toString(16);
  if (xStr.length % 2 == 1) {
    xStr = '0' + xStr;
  }
  if (xStr.length / 2 > xLen) {
    throw 'integer too long';
  }
  if (xStr.length / 2 < xLen) {
    xStr = '00'.repeat(xLen - xStr.length / 2) + xStr;
  }
  const ans = new Uint8Array(xLen);
  for (let i = 0; i < xLen; i++) {
    ans[i] = parseInt(xStr.substr(i * 2, 2), 16);
  }
  return ans;
}