import {
  equalsJWAAlgSpecificJOSEHeader,
  isPartialJWAAlgSpecificJOSEHeader,
  JWAAlgSpecificJOSEHeader,
  JWAAlgSpecificJOSEHeaderParamNames,
} from 'jwa/sec4/header';
import {
  equalsJWEJOSEHeader,
  isPartialJWEJOSEHeader,
  JWEJOSEHeader,
  JWEJOSEHeaderParamNames,
} from 'jwe/type';
import {
  equalsJWSJOSEHeader,
  isPartialJWSJOSEHeader,
  JWSJOSEHeader,
  JWSJOSEHeaderParamNames,
} from 'jws/type';

export { JOSEHeader, isJOSEHeader, equalsJOSEHeader, JOSEHeaderParamName, isJOSEHeaderParamName };

/**
 * 暗号操作や使用されるパラメータを表現する JSON オブジェクト
 */
type JOSEHeader<T extends 'JWS' | 'JWE' = 'JWS' | 'JWE'> = T extends 'JWS'
  ? Partial<JWSJOSEHeader>
  : T extends 'JWE'
  ? Partial<JWEJOSEHeader & JWAAlgSpecificJOSEHeader>
  : never;

const equalsJOSEHeader = (l?: JOSEHeader, r?: JOSEHeader): boolean => {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  if (isJOSEHeader(l, 'JWS')) {
    if (!isJOSEHeader(r, 'JWS')) return false;
    return equalsJWSJOSEHeader(l, r);
  } else if (isJOSEHeader(l, 'JWE')) {
    if (!isJOSEHeader(r, 'JWE')) return false;
    return equalsJWEJOSEHeader(l, r) && equalsJWAAlgSpecificJOSEHeader(l, r);
  }
  return false;
};

function isJOSEHeader<T extends 'JWS' | 'JWE'>(arg: unknown, t?: T): arg is JOSEHeader<T> {
  if (t === 'JWE') {
    return isPartialJWEJOSEHeader(arg) && isPartialJWAAlgSpecificJOSEHeader(arg);
  }
  // TODO;
  if (t === 'JWS') {
    return isPartialJWSJOSEHeader(arg);
  }
  return (
    isPartialJWSJOSEHeader(arg) ||
    (isPartialJWEJOSEHeader(arg) && isPartialJWAAlgSpecificJOSEHeader(arg))
  );
}

type JOSEHeaderParamName<T extends 'JWS' | 'JWE' = 'JWS' | 'JWE'> = keyof JOSEHeader<T>;

function isJOSEHeaderParamName<T extends 'JWS' | 'JWE'>(
  arg: unknown,
  t?: T
): arg is JOSEHeaderParamName<T> {
  if (t === 'JWE') {
    return [...JWEJOSEHeaderParamNames, ...JWAAlgSpecificJOSEHeaderParamNames].some(
      (n) => n === arg
    );
  }
  if (t === 'JWS') {
    return [...JWSJOSEHeaderParamNames].some((n) => n === arg);
  }
  return [
    ...JWEJOSEHeaderParamNames,
    ...JWAAlgSpecificJOSEHeaderParamNames,
    ...JWSJOSEHeaderParamNames,
  ].some((n) => n === arg);
}
