import { isObject } from 'utility';

export {
  PBES2HeaderParams,
  PBES2HeaderParamNames,
  isPartialPBES2HeaderParams,
  isPBES2HeaderParams,
  equalsPBES2HeaderParams,
};
/**
 * RFC7518#4.8.1 PBES2 Key Encryption 用のヘッダーパラメータ
 */
type PBES2HeaderParams = {
  /**
   * RFC7518#4.8.1.2 PBES2 Count Header Parameter は PBKDF2 iteration count を表現する。
   * 最小反復回数は 1000 が推奨されている (RFC2898)
   */
  p2c: number;
  /**
   * RFC7518#4.8.1.1 PBES2 Salt Input Header Parameter は PBKDF2 salt input を BASE64URL エンコードしている。
   * 使用される salt value は UTF8(Alg) || 0x00 || Salt Input である。
   */
  p2s: string;
};

const PBES2HeaderParamNames = ['p2c', 'p2s'] as const;

const isPBES2HeaderParams = (arg: unknown): arg is PBES2HeaderParams =>
  isPartialPBES2HeaderParams(arg) && arg.p2c != null && arg.p2s != null;

const isPartialPBES2HeaderParams = (arg: unknown): arg is Partial<PBES2HeaderParams> =>
  isObject<PBES2HeaderParams>(arg) &&
  PBES2HeaderParamNames.every(
    (n) => !arg[n] || (n === 'p2c' ? typeof arg[n] === 'number' : typeof arg[n] === 'string')
  );

function equalsPBES2HeaderParams(
  l?: Partial<PBES2HeaderParams>,
  r?: Partial<PBES2HeaderParams>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return l.p2c === r.p2c && l.p2s === r.p2s;
}
