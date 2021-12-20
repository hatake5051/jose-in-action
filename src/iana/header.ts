import {
  equalsJWAAlgSpecificJOSEHeaderParams,
  isPartialJWAAlgSpecificJOSEHeaderParams,
  JWAAlgSpecificJOSEHeaderParamNames,
  JWAAlgSpecificJOSEHeaderParams,
} from 'jwa/sec4/header';
import {
  equalsJWEJOSEHeaderParams,
  isPartialJWEJOSEHeaderParams,
  JWEJOSEHeaderParamNames,
  JWEJOSEHeaderParams,
} from 'jwe/header';
import {
  equalsJWSJOSEHeaderParams,
  isPartialJWSJOSEHeaderParams,
  JWSJOSEHeaderParamNames,
  JWSJOSEHeaderParams,
} from 'jws/type';

export {
  JOSEHeaderParams,
  isJOSEHeaderParams,
  equalsJOSEHeaderParams,
  JOSEHeaderParamName,
  isJOSEHeaderParamName,
};

/**
 * 暗号操作や使用されるパラメータを表現する JSON オブジェクト
 */
type JOSEHeaderParams<T extends 'JWS' | 'JWE' = 'JWS' | 'JWE'> = T extends 'JWS'
  ? Partial<JWSJOSEHeaderParams>
  : T extends 'JWE'
  ? Partial<JWEJOSEHeaderParams & JWAAlgSpecificJOSEHeaderParams>
  : never;

const equalsJOSEHeaderParams = (l?: JOSEHeaderParams, r?: JOSEHeaderParams): boolean => {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  if (isJOSEHeaderParams(l, 'JWS')) {
    if (!isJOSEHeaderParams(r, 'JWS')) return false;
    return equalsJWSJOSEHeaderParams(l, r);
  } else if (isJOSEHeaderParams(l, 'JWE')) {
    if (!isJOSEHeaderParams(r, 'JWE')) return false;
    return equalsJWEJOSEHeaderParams(l, r) && equalsJWAAlgSpecificJOSEHeaderParams(l, r);
  }
  return false;
};

function isJOSEHeaderParams<T extends 'JWS' | 'JWE'>(
  arg: unknown,
  t?: T
): arg is JOSEHeaderParams<T> {
  const isJWE = (arg: unknown) =>
    isPartialJWEJOSEHeaderParams(arg) && isPartialJWAAlgSpecificJOSEHeaderParams(arg);
  const isJWS = (arg: unknown) => isPartialJWSJOSEHeaderParams(arg);
  if (t === 'JWE') {
    return isJWE(arg);
  }
  if (t === 'JWS') {
    return isJWS(arg);
  }
  return isJWE(arg) || isJWS(arg);
}

type JOSEHeaderParamName<T extends 'JWS' | 'JWE' = 'JWS' | 'JWE'> = keyof JOSEHeaderParams<T>;

function isJOSEHeaderParamName<T extends 'JWS' | 'JWE'>(
  arg: unknown,
  t?: T
): arg is JOSEHeaderParamName<T> {
  const jwe = [...JWEJOSEHeaderParamNames, ...JWAAlgSpecificJOSEHeaderParamNames];
  const jws = [...JWSJOSEHeaderParamNames];
  if (t === 'JWE') {
    return jwe.some((n) => n === arg);
  }
  if (t === 'JWS') {
    return jws.some((n) => n === arg);
  }
  return [...jws, ...jwe].some((n) => n === arg);
}
