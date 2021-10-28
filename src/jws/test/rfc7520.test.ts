import {
  equalsJWSJOSEHeader,
  JWS,
  JWSCompactSerialization,
  JWSFlattenedJSONSerialization,
  JWSJSONSerialization,
  JWSProtectedHeader,
  JWSUnprotectedHeader,
} from '..';
import { Alg, isAlg } from '../../iana';
import { exportPublicKey, isJWK, JWK, JWKSet } from '../../jwk';
import { isObject, UTF8 } from '../../util';
import { isJWSProtectedHeader, isJWSUnprotectedHeader } from '../internal/header';
import {
  equalsJWSFlattenedJSONSerialization,
  equalsJWSJSONSerialization,
  isJWSFlattenedJSONSerialization,
  isJWSJSONSerialization,
} from '../internal/serialize';

export { sec4 };

async function sec4() {
  const baseURL = 'https://raw.githubusercontent.com/ietf-jose/cookbook/master/jws/';
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

  const fetchData = async (path: string): Promise<unknown> =>
    await (await fetch(baseURL + path)).json();
  for (const path of paths) {
    console.group('TEST NAME:', path);
    const data = await fetchData(path);
    if (!isData(data)) throw new EvalError('適切なテストデータの読み取りに失敗');
    const payload = UTF8(data.input.payload);
    let header;
    if (Array.isArray(data.signing)) {
      header = data.signing.map((sig) => ({ p: sig.protected, u: sig.unprotected }));
    } else {
      header = { p: data.signing.protected, u: data.signing.unprotected };
    }
    const keys: JWKSet = {
      keys: Array.isArray(data.input.key) ? data.input.key : [data.input.key],
    };
    const jws = await JWS.produce(keys, payload, header);
    console.log('JWS を生成する', jws);

    const verifyKeys: JWKSet = {
      keys: keys.keys.map((k) => {
        if (isJWK<'oct', 'Pub' | 'Priv'>(k, 'oct')) return k;
        if (isJWK<'EC' | 'RSA', 'Priv'>(k, k.kty)) return exportPublicKey(k);
        throw TypeError(`JWK ではない鍵が紛れ込んでいる $key`);
      }),
    };

    let isAllGreen = true;
    if (data.reproducible) {
      console.log('テストには再現性があるため、シリアライズした結果を比較する');
      const output = data.output;
      if (output.compact) {
        const compact = jws.serialize('compact');
        const same = output.compact === compact;
        isAllGreen &&= same;
        console.log('Compact Serialiation:', same);
      }
      if (output.json) {
        const json = jws.serialize('json');
        const same = equalsJWSJSONSerialization(output.json, json);
        isAllGreen &&= same;
        console.log('JSON Serialization:', same);
        console.log('JSON Serialization:', json);
      }
      if (output.json_flat) {
        const flat = jws.serialize('json-flat');
        const same = equalsJWSFlattenedJSONSerialization(output.json_flat, flat);
        isAllGreen &&= same;
        console.log('Flattened JSON Serializatio:', same);
        console.log(equalsJWSJOSEHeader(flat.header, flat.header));
        console.log('Flattened JSON Serializatio:', flat);
      }
    } else {
      console.log('テストには再現性がない (e.g. 署名アルゴリズムに乱数がからむ)');
    }
    console.log('JWS の検証する');
    const valid = await jws.validate(verifyKeys);
    isAllGreen &&= valid;
    console.log('JWS Produce and Validation ', valid);
    const output = data.output;
    if (output.compact) {
      const jws = JWS.deserialize(output.compact);
      const valid = await jws.validate(verifyKeys);
      isAllGreen &&= valid;
      console.log('Compact Deserialization and Validation:', valid);
    }
    if (output.json) {
      const jws = JWS.deserialize(output.json);
      const valid = await jws.validate(verifyKeys);
      isAllGreen &&= valid;
      console.log('JSON Deserialization and Validation', valid);
    }
    if (output.json_flat) {
      const jws = JWS.deserialize(output.json_flat);
      const valid = await jws.validate(verifyKeys);
      isAllGreen &&= valid;
      console.log('Flattened JSON Deserialization and Validation', valid);
    }
    console.log('TEST NAME:', path, 'Is All Green?', isAllGreen);
    console.groupEnd();
  }
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
