import {
  AGCMKWHeaderParamNames,
  AGCMKWHeaderParams,
  equalsAGCMKWHeaderParams,
  isAGCMKWHeaderParams,
  isPartialAGCMKWHeaderParams,
} from './aesgcm/header';
import {
  ECDH_ESHeaderParamNames,
  ECDH_ESHeaderParams,
  equalsECDH_ESHeaderParams,
  isECDH_ESHeaderParams,
  isPartialECDH_ESHeaderParams,
} from './ecdh/header';
import {
  equalsPBES2HeaderParams,
  isPartialPBES2HeaderParams,
  isPBES2HeaderParams,
  PBES2HeaderParamNames,
  PBES2HeaderParams,
} from './pbes2/header';

export {
  JWAAlgSpecificJOSEHeader,
  JWAAlgSpecificJOSEHeaderParamNames,
  isPartialJWAAlgSpecificJOSEHeader,
  isJWAAlgSpecificJOSEHeader,
  equalsJWAAlgSpecificJOSEHeader,
};

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
