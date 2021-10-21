import { Crv } from '../../iana';
import { BASE64URL_DECODE } from '../../util';
import { CommomJWKParams, isCommonJWKParams } from './common';

/**
 * RFC7518#6.2.1
 * EC 公開鍵が持つパラメータを定義する。
 */
type ECPublicKeyParams = {
  /**
   * RFC7518#6.2.1.1
   * Curve parameter はこの鍵で用いる curve を識別する。
   * JSON Web Key Eliptic Curve レジストリに登録されているもののいずれかである。
   */
  crv: Crv;
  /**
   * RFC7518#6.2.1.2
   * X Coordinate parameter は楕円曲線点のx座標を表す。
   * 値は座標のオクテット表現のBASE64URL encode されたものを持つ。
   * crv によって座標のオクテット表現の長さは固定である。
   */
  x: string;
  /**
   * RFC7518#6.2.1.3
   * Y Coordinate parameter は楕円曲線点のy座標を表す。
   * 値は座標のオクテット表現の BASE64URL encode されたものを持つ。
   * crv によって座標のオクテット表現の長さは固定である。
   */
  y: string;
};
const ecPublicKeyParams = ['crv', 'x', 'y'];

function validECPublicKeyParams(p: ECPublicKeyParams): boolean {
  let key_len;
  switch (p.crv) {
    case 'P-256':
      key_len = 32;
      break;
    case 'P-384':
      key_len = 48;
      break;
    case 'P-521':
      key_len = 66;
      break;
  }
  return (
    BASE64URL_DECODE(p.x).length === key_len &&
    BASE64URL_DECODE(p.y).length === key_len
  );
}

/**
 * RFC7518#6.2.2
 * EC 秘密鍵が持つパラメータを定義する。
 */
type ECPrivateKeyParams = {
  /**
   * RFC7518#6.2.2.1
   * ECC Private Key parameter は楕円曲線の private key value が含まれる。
   * 値は private key value のオクテット表現の base64url encode されたものを持つ。
   * crv によってオクテット表現の長さは固定である。
   */
  d: string;
};

function validECPrivateKeyParams(crv: Crv, p: ECPrivateKeyParams): boolean {
  let key_len;
  switch (crv) {
    case 'P-256':
      key_len = 32;
      break;
    case 'P-384':
      key_len = 48;
      break;
    case 'P-521':
      key_len = 66;
      break;
  }
  return BASE64URL_DECODE(p.d).length === key_len;
}

type ECPublicKey = CommomJWKParams<'EC'> & ECPublicKeyParams;

const isECPublicKey = (arg: unknown): arg is ECPublicKey => {
  if (!isCommonJWKParams(arg) || arg.kty !== 'EC') return false;
  if (!ecPublicKeyParams.every((key) => key in arg)) return false;
  return validECPublicKeyParams(arg as ECPublicKey);
};

type ECPrivateKey = ECPublicKey & ECPrivateKeyParams;

const isECPrivateKey = (arg: unknown): arg is ECPrivateKey => {
  if (!isECPublicKey(arg)) return false;
  const crv = arg.crv;
  if (!('d' in arg)) return false;
  return validECPrivateKeyParams(crv, arg as ECPrivateKey);
};

export { ECPublicKey, isECPublicKey, ECPrivateKey, isECPrivateKey };
