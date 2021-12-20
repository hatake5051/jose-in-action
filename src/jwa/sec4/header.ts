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
  JWAAlgSpecificJOSEHeaderParams,
  JWAAlgSpecificJOSEHeaderParamNames,
  isPartialJWAAlgSpecificJOSEHeaderParams,
  isJWAAlgSpecificJOSEHeaderParams,
  equalsJWAAlgSpecificJOSEHeaderParams,
};

type JWAAlgSpecificJOSEHeaderParams = AGCMKWHeaderParams & ECDH_ESHeaderParams & PBES2HeaderParams;

const JWAAlgSpecificJOSEHeaderParamNames = [
  ...AGCMKWHeaderParamNames,
  ...ECDH_ESHeaderParamNames,
  ...PBES2HeaderParamNames,
] as const;

const isPartialJWAAlgSpecificJOSEHeaderParams = (
  arg: unknown
): arg is Partial<JWAAlgSpecificJOSEHeaderParams> =>
  isPartialAGCMKWHeaderParams(arg) ||
  isPartialECDH_ESHeaderParams(arg) ||
  isPartialPBES2HeaderParams(arg);

const isJWAAlgSpecificJOSEHeaderParams = (arg: unknown): arg is JWAAlgSpecificJOSEHeaderParams =>
  isAGCMKWHeaderParams(arg) || isECDH_ESHeaderParams(arg) || isPBES2HeaderParams(arg);

const equalsJWAAlgSpecificJOSEHeaderParams = (
  l?: Partial<JWAAlgSpecificJOSEHeaderParams>,
  r?: Partial<JWAAlgSpecificJOSEHeaderParams>
): boolean =>
  equalsAGCMKWHeaderParams(l, r) ||
  equalsECDH_ESHeaderParams(l, r) ||
  equalsPBES2HeaderParams(l, r);
