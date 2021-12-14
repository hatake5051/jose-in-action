import {
  DirectEncryptor,
  DirectKeyAgreementer,
  KeyAgreementerWithKeyWrapping,
  KeyEncryptor,
  KeyMgmtMode,
  KeyWrapper,
} from 'jwe/ineterface';
import { JWECEK } from 'jwe/type';
import { JWK } from 'jwk';
import { BASE64URL_DECODE } from 'utility';
import {
  AGCMKeyWrapper,
  AGCMKWAlg,
  AGCMKWHeaderParamNames,
  AGCMKWHeaderParams,
  equalsAGCMKWHeaderParams,
  isAGCMKWAlg,
  isAGCMKWHeaderParams,
  isPartialAGCMKWHeaderParams,
} from './aesgcm';
import { AKWAlg, AKWKeyWrapper, isAKWAlg } from './aeskw';
import {
  ECDHDirectKeyAgreementer,
  ECDHKeyAgreementerWithKeyWrapping,
  ECDH_ESAlg,
  ECDH_ESHeaderParamNames,
  ECDH_ESHeaderParams,
  ECDH_ESKWAlg,
  equalsECDH_ESHeaderParams,
  isECDH_ESAlg,
  isECDH_ESHeaderParams,
  isECDH_ESKWAlg,
  isPartialECDH_ESHeaderParams,
} from './ecdh';
import {
  equalsPBES2HeaderParams,
  isPartialPBES2HeaderParams,
  isPBES2Alg,
  isPBES2HeaderParams,
  PBES2Alg,
  PBES2HeaderParamNames,
  PBES2HeaderParams,
  PBES2KeyWrapper,
} from './pbes2';
import { isRSA1_5Alg, isRSAOAEPAlg, RSA1_5Alg, RSAKeyEncryptor, RSAOAEPAlg } from './rsa';

export {
  JWAKEAlg,
  isJWAKEAlg,
  JWAKWAlg,
  isJWAKWAlg,
  JWADKAAlg,
  isJWADKAAlg,
  JWAKAKWAlg,
  isJWAKAKWAlg,
  JWADEAlg,
  isJWADEAlg,
  KtyFromJWAJWEAlg,
  ktyFromJWAJWEAlg,
  JWAAlgSpecificJOSEHeader,
  JWAAlgSpecificJOSEHeaderParamNames,
  isPartialJWAAlgSpecificJOSEHeader,
  isJWAAlgSpecificJOSEHeader,
  equalsJWAAlgSpecificJOSEHeader,
  keyMgmtModeFromJWAAlg,
  newJWAKeyEncryptor,
  newJWAKeyWrapper,
  newJWADirectAgreementer,
  newJWAKeyAgreementerWithKeyWrapping,
  newJWADirectEncryptor,
};

type JWAKEAlg = RSA1_5Alg | RSAOAEPAlg;

const isJWAKEAlg = (arg: unknown): arg is JWAKEAlg => isRSA1_5Alg(arg) || isRSAOAEPAlg(arg);

function newJWAKeyEncryptor<A extends JWAKEAlg>(alg: A): KeyEncryptor<A> {
  if (isRSA1_5Alg(alg) || isRSAOAEPAlg(alg)) return RSAKeyEncryptor as KeyEncryptor<A>;
  throw TypeError(`KeyEncryptor<$alg> は実装されていない`);
}

type JWAKWAlg = AKWAlg | AGCMKWAlg | PBES2Alg;
const isJWAKWAlg = (arg: unknown): arg is JWAKWAlg =>
  isAKWAlg(arg) || isAGCMKWAlg(arg) || isPBES2Alg(arg);

function newJWAKeyWrapper<A extends JWAKWAlg>(alg: A): KeyWrapper<A> {
  if (isAKWAlg(alg)) return AKWKeyWrapper as KeyWrapper<A>;
  if (isAGCMKWAlg(alg)) return AGCMKeyWrapper as KeyWrapper<A>;
  if (isPBES2Alg(alg)) return PBES2KeyWrapper as KeyWrapper<A>;
  throw TypeError(`KeyWrapper<$alg> is not implemented`);
}

type JWADKAAlg = ECDH_ESAlg;
const isJWADKAAlg = (arg: unknown): arg is JWADKAAlg => isECDH_ESAlg(arg);

function newJWADirectAgreementer<A extends JWADKAAlg>(alg: A): DirectKeyAgreementer<A> {
  if (isECDH_ESAlg(alg)) return ECDHDirectKeyAgreementer as unknown as DirectKeyAgreementer<A>;
  throw TypeError(`KeyAgreement<$alg> is not implemented`);
}

type JWAKAKWAlg = ECDH_ESKWAlg;
const isJWAKAKWAlg = (arg: unknown): arg is JWAKAKWAlg => isECDH_ESKWAlg(arg);

function newJWAKeyAgreementerWithKeyWrapping<A extends JWAKAKWAlg>(
  alg: A
): KeyAgreementerWithKeyWrapping<A> {
  if (isECDH_ESKWAlg(alg))
    return ECDHKeyAgreementerWithKeyWrapping as unknown as KeyAgreementerWithKeyWrapping<A>;
  throw TypeError(`KeyAgreementerWithKeyWrapping<$alg> is not implemented`);
}

type JWADEAlg = 'dir';
const isJWADEAlg = (arg: unknown): arg is JWADEAlg => typeof arg === 'string' && arg === 'dir';

function newJWADirectEncryptor<A extends JWADEAlg>(alg: A): DirectEncryptor<A> {
  if (isJWADEAlg(alg))
    return {
      extract: async (alg: A, key: JWK<'oct'>) => BASE64URL_DECODE(key.k) as JWECEK,
    } as DirectEncryptor<A>;
  throw TypeError(`DirecyEncryptor<$alg> is not implemented`);
}

type KtyFromJWAJWEAlg<A extends JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg> =
  A extends JWAKEAlg
    ? 'RSA'
    : A extends JWAKWAlg | JWADEAlg
    ? 'oct'
    : A extends JWADKAAlg | JWAKAKWAlg
    ? 'EC'
    : never;

function ktyFromJWAJWEAlg<A extends JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg>(
  alg: A
): KtyFromJWAJWEAlg<A> {
  if (isJWAKEAlg(alg)) return 'RSA' as KtyFromJWAJWEAlg<A>;
  if (isJWAKWAlg(alg) || isJWADEAlg(alg)) return 'oct' as KtyFromJWAJWEAlg<A>;
  if (isJWADKAAlg(alg) || isJWAKAKWAlg(alg)) return 'EC' as KtyFromJWAJWEAlg<A>;
  throw new TypeError(`${alg} に対応する鍵の kty がわからなかった`);
}

type JWAAlgSpecificJOSEHeader = AGCMKWHeaderParams & ECDH_ESHeaderParams & PBES2HeaderParams;

const JWAAlgSpecificJOSEHeaderParamNames = [
  ...AGCMKWHeaderParamNames,
  ...ECDH_ESHeaderParamNames,
  ...PBES2HeaderParamNames,
] as const;

const isPartialJWAAlgSpecificJOSEHeader = (
  arg: unknown
): arg is Partial<JWAAlgSpecificJOSEHeader> =>
  isPartialAGCMKWHeaderParams(arg) ||
  isPartialECDH_ESHeaderParams(arg) ||
  isPartialPBES2HeaderParams(arg);

const isJWAAlgSpecificJOSEHeader = (arg: unknown): arg is JWAAlgSpecificJOSEHeader =>
  isAGCMKWHeaderParams(arg) || isECDH_ESHeaderParams(arg) || isPBES2HeaderParams(arg);

const equalsJWAAlgSpecificJOSEHeader = (
  l?: Partial<JWAAlgSpecificJOSEHeader>,
  r?: Partial<JWAAlgSpecificJOSEHeader>
): boolean =>
  equalsAGCMKWHeaderParams(l, r) ||
  equalsECDH_ESHeaderParams(l, r) ||
  equalsPBES2HeaderParams(l, r);

function keyMgmtModeFromJWAAlg(
  alg: JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg
): KeyMgmtMode {
  if (isJWAKEAlg(alg)) return 'KE';
  if (isJWAKWAlg(alg)) return 'KW';
  if (isJWADKAAlg(alg)) return 'DKA';
  if (isJWAKAKWAlg(alg)) return 'KAKW';
  if (isJWADEAlg(alg)) return 'DE';
  const a: never = alg;
  throw new TypeError(`${a} の Key Management Mode がわからない`);
}
