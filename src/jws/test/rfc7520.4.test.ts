import { Alg, isAlg } from 'iana';
import { isJWK, JWK, JWKSet } from 'jwk';
import {
  isJWSFlattenedJSONSerialization,
  isJWSJSONSerialization,
  isJWSProtectedHeader,
  isJWSUnprotectedHeader,
  JWSCompactSerialization,
  JWSFlattenedJSONSerialization,
  JWSJSONSerialization,
  JWSProtectedHeader,
  JWSUnprotectedHeader,
} from 'jws';
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
    alg: Alg | Alg[];
  };
  signing:
    | {
        protected?: JWSProtectedHeader;
        unprotected?: JWSUnprotectedHeader;
      }
    | {
        protected?: JWSProtectedHeader;
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
    isObject<{ payload: string; key: JWK | JWKSet; alg: Alg }>(arg.input) &&
    typeof arg.input.payload === 'string' &&
    (Array.isArray(arg.input.key)
      ? arg.input.key.every((k: unknown) => isJWK(k))
      : isJWK(arg.input.key)) &&
    (Array.isArray(arg.input.alg)
      ? arg.input.alg.every((a: unknown) => isAlg(a))
      : isAlg(arg.input.alg)) &&
    isObject<
      | { protected?: JWSProtectedHeader; unprotected?: JWSUnprotectedHeader }
      | { protected?: JWSProtectedHeader; unprotected?: JWSUnprotectedHeader }[]
    >(arg.signing) &&
    (Array.isArray(arg.signing)
      ? arg.signing.every(
          (s: unknown) =>
            isObject<{ protected?: JWSProtectedHeader; unprotected?: JWSUnprotectedHeader }>(s) &&
            (s.protected == null || isJWSProtectedHeader(s.protected)) &&
            (s.unprotected == null || isJWSUnprotectedHeader(s.unprotected))
        )
      : (arg.signing.protected == null || isJWSProtectedHeader(arg.signing.protected)) &&
        (arg.signing.unprotected == null || isJWSUnprotectedHeader(arg.signing.unprotected))) &&
    isObject<{
      compact?: JWSCompactSerialization;
      json: JWSJSONSerialization;
      json_flat: JWSFlattenedJSONSerialization;
    }>(arg.output) &&
    (arg.output.compact == null || typeof arg.output.compact === 'string') &&
    isJWSJSONSerialization(arg.output.json) &&
    (arg.output.json_flat == null || isJWSFlattenedJSONSerialization(arg.output.json_flat))
  );
}
