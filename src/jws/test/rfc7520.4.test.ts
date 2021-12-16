// --------------------BEGIN RFC7520 Section 4 test data definition --------------------

import { Alg, isAlg, isJOSEHeader } from 'iana';
import { isJWK, JWK } from 'jwk';
import { JWSFlattenedJSONSerializer, JWSJSONSerializer } from 'jws';
import {
  JWSCompactSerialization,
  JWSFlattenedJSONSerialization,
  JWSJSONSerialization,
  JWSProtectedHeader,
  JWSUnprotectedHeader,
} from 'jws/type';
import { isObject } from 'utility';

export { fetchData, paths };

const paths = [
  '4_1.rsa_v15_signature.json',
  '4_2.rsa-pss_signature.json',
  '4_3.ecdsa_signature.json',
  '4_4.hmac-sha2_integrity_protection.json',
  // "4_5.signature_with_detached_content.json",
  '4_6.protecting_specific_header_fields.json',
  '4_7.protecting_content_only.json',
  '4_8.multiple_signatures.json',
];

const baseURL = 'https://raw.githubusercontent.com/ietf-jose/cookbook/master/jws/';

async function fetchData(path: string): Promise<Data> {
  const resp = await fetch(baseURL + path);
  const data: unknown = await resp.json();
  if (isData(data)) return data;
  throw new EvalError('テストデータの取得に失敗');
}

type Data = {
  title: string;
  reproducible?: boolean;
  input: {
    payload: string;
    key: JWK | JWK[];
    alg: Alg<'JWS'> | Alg<'JWS'>[];
  };
  signing:
    | {
        protected?: JWSProtectedHeader;
        protected_b64u?: string;
        unprotected?: JWSUnprotectedHeader;
      }
    | {
        protected?: JWSProtectedHeader;
        protected_b64u?: string;
        unprotected?: JWSUnprotectedHeader;
      }[];
  output: {
    compact?: JWSCompactSerialization;
    json: JWSJSONSerialization;
    json_flat: JWSFlattenedJSONSerialization;
  };
};

function isData(arg: unknown): arg is Data {
  return (
    isObject<Data>(arg) &&
    typeof arg.title === 'string' &&
    (arg.reproducible == null || typeof arg.reproducible === 'boolean') &&
    isObject<Data['input']>(arg.input) &&
    typeof arg.input.payload === 'string' &&
    (Array.isArray(arg.input.key)
      ? arg.input.key.every((k: unknown) => isJWK(k))
      : isJWK(arg.input.key)) &&
    (Array.isArray(arg.input.alg)
      ? arg.input.alg.every((a: unknown) => isAlg(a))
      : isAlg(arg.input.alg)) &&
    isObject<Data['signing']>(arg.signing) &&
    (Array.isArray(arg.signing)
      ? arg.signing.every(
          (s) =>
            isObject<{
              protected?: JWSProtectedHeader;
              protected_b64u?: string;
              unprotected?: JWSUnprotectedHeader;
            }>(s) &&
            (s.protected == null || isJOSEHeader(s.protected, 'JWS')) &&
            (s.protected_b64u == null || typeof s.protected_b64u === 'string') &&
            (s.unprotected == null || isJOSEHeader(s.unprotected, 'JWS'))
        )
      : (arg.signing.protected == null || isJOSEHeader(arg.signing.protected, 'JWS')) &&
        (arg.signing.protected_b64u == null || typeof arg.signing.protected_b64u === 'string') &&
        (arg.signing.unprotected == null || isJOSEHeader(arg.signing.unprotected, 'JWS'))) &&
    isObject<Data['output']>(arg.output) &&
    (arg.output.compact == null || typeof arg.output.compact === 'string') &&
    JWSJSONSerializer.is(arg.output.json) &&
    (arg.output.json_flat == null || JWSFlattenedJSONSerializer.is(arg.output.json_flat))
  );
}

// --------------------END RFC7520 Section 4 test data definition --------------------
