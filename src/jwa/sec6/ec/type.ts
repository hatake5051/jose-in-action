import { Crv, isCrv, keylenOfCrv } from 'iana/crv';
import { BASE64URL_DECODE, isObject } from 'utility';

export {
  JWAECPubKeyParams,
  isJWAECPubKeyParams,
  isPartialJWAECPubKeyParams,
  equalsJWAECPubKeyParams,
  JWAECPrivKeyParams,
  isJWAECPrivKeyParams,
  isPartialJWAECPrivKeyParams,
  equalsJWAECPrivKeyParams,
  exportJWAECPubKeyParams,
};

/**
 * RFC7518#6.2.1
 * EC 公開鍵が持つパラメータを定義する。
 */
type JWAECPubKeyParams = {
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
} & { _brand: 'JWAECPubKeyParams' };

const JWAECPubKeyParamNames = ['crv', 'x', 'y'] as const;

function isPartialJWAECPubKeyParams(arg: unknown): arg is Partial<JWAECPubKeyParams> {
  if (!isObject<JWAECPubKeyParams>(arg)) return false;
  if (arg.crv) {
    if (!isCrv(arg.crv)) return false;
    return (['x', 'y'] as const).every((n) => {
      const x = arg[n];
      try {
        return typeof x === 'string' && BASE64URL_DECODE(x).length === keylenOfCrv(arg.crv as Crv);
      } catch {
        return false;
      }
    });
  }
  return (['x', 'y'] as const).every((n) => arg[n] == null || typeof arg[n] === 'string');
}

const isJWAECPubKeyParams = (arg: unknown): arg is JWAECPubKeyParams =>
  isPartialJWAECPubKeyParams(arg) && JWAECPubKeyParamNames.every((n) => arg[n] != null);

function equalsJWAECPubKeyParams(
  l?: Partial<JWAECPubKeyParams>,
  r?: Partial<JWAECPubKeyParams>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return JWAECPubKeyParamNames.every((n) => l[n] === r[n]);
}

/**
 * RFC7518#6.2.2
 * EC 秘密鍵が持つパラメータを定義する。
 */
type JWAECPrivKeyParams = {
  /**
   * RFC7518#6.2.2.1
   * ECC Private Key parameter は楕円曲線の private key value が含まれる。
   * 値は private key value のオクテット表現の base64url encode されたものを持つ。
   * crv によってオクテット表現の長さは固定である。
   */
  d: string;
} & Omit<JWAECPubKeyParams, '_brand'> & { _brand: 'JWAECPrivKeyParams' };

const JWAECPrivKeyParamNames = ['d', ...JWAECPubKeyParamNames] as const;

function isPartialJWAECPrivKeyParams(arg: unknown): arg is Partial<JWAECPrivKeyParams> {
  if (!isObject<Partial<JWAECPrivKeyParams>>(arg)) return false;
  const d = arg.d;
  if (!isPartialJWAECPubKeyParams(arg)) return false;
  if (arg.crv) {
    try {
      return typeof d === 'string' && BASE64URL_DECODE(d).length === keylenOfCrv(arg.crv as Crv);
    } catch {
      return false;
    }
  }
  return d == null || typeof d === 'string';
}

const isJWAECPrivKeyParams = (arg: unknown): arg is JWAECPrivKeyParams =>
  isPartialJWAECPrivKeyParams(arg) && JWAECPrivKeyParamNames.every((n) => arg[n] != null);

function equalsJWAECPrivKeyParams(
  l?: Partial<JWAECPrivKeyParams>,
  r?: Partial<JWAECPrivKeyParams>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return JWAECPrivKeyParamNames.every((n) => l[n] === r[n]);
}

function exportJWAECPubKeyParams(priv: JWAECPrivKeyParams): JWAECPubKeyParams {
  let pub: Partial<JWAECPubKeyParams> = {};
  JWAECPubKeyParamNames.forEach((n) => {
    pub = { ...pub, [n]: priv[n] };
  });
  if (isJWAECPubKeyParams(pub)) return pub;
  throw new TypeError('JWAECPrivKeyParams から公開鍵情報を取り出せませんでした');
}
