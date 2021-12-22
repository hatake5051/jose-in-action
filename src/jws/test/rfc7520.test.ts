// --------------------BEGIN RFC7520 Section 4 test --------------------

import { exportPubJWK, isJWK, JWKSet } from 'jwk';
import { JWS, JWSFlattenedJSONSerializer, JWSJSONSerializer } from 'jws';
import { JWSPayload } from 'jws/type';
import { UTF8 } from 'utility';
import { fetchData } from './rfc7520.4.test';

export { test };

async function test(path: string): Promise<{
  title: string;
  log: string;
  allGreen: boolean;
}> {
  const data = await fetchData(path);
  let allGreen = true;
  const title = 'RFC7520#4 TEST NAME: ' + data.title;
  let log = '';
  // 準備
  const payload = UTF8(data.input.payload) as JWSPayload;
  const options: Parameters<typeof JWS.produce>[3] = {
    header: Array.isArray(data.signing)
      ? data.signing.map((s) => ({
          p: s.protected
            ? {
                initialValue: s.protected,
                b64u: s.protected_b64u,
              }
            : undefined,
          u: s.unprotected
            ? {
                initialValue: s.unprotected,
              }
            : undefined,
        }))
      : {
          p: data.signing.protected
            ? {
                initialValue: data.signing.protected,
                b64u: data.signing.protected_b64u,
              }
            : undefined,
          u: data.signing.unprotected
            ? {
                initialValue: data.signing.unprotected,
              }
            : undefined,
        },
  };

  const keys: JWKSet = {
    keys: Array.isArray(data.input.key) ? data.input.key : [data.input.key],
  };
  // 生成
  const jws = await JWS.produce(data.input.alg, keys, payload, options);

  // 検証の準備
  const verifyKeys: JWKSet = {
    keys: keys.keys.map((k) => {
      if (isJWK(k, 'Priv')) return exportPubJWK(k);
      if (isJWK(k, 'Pub')) return k;
      throw TypeError(`JWK ではない鍵が紛れ込んでいる ${k}`);
    }),
  };

  if (data.reproducible) {
    log += 'テストには再現性があるため、シリアライズした結果を比較する\n';
    const output = data.output;
    if (output.compact) {
      const compact = jws.serialize('compact');
      const same = output.compact === compact;
      allGreen &&= same;
      log += 'Compact: ' + (same ? '(OK) ' : 'X ');
    }
    if (output.json) {
      const json = jws.serialize('json');
      const same = JWSJSONSerializer.equals(output.json, json);
      allGreen &&= same;
      log += 'JSON: ' + (same ? '(OK) ' : 'X ');
    }
    if (output.json_flat) {
      const flat = jws.serialize('json_flat');
      const same = JWSFlattenedJSONSerializer.equals(output.json_flat, flat);
      allGreen &&= same;
      log += 'FlattenedJSON: ' + (same ? '(OK) ' : 'X ');
    }
    log += '\n';
  } else {
    log += 'テストには再現性がない (e.g. 署名アルゴリズムに乱数がからむ)\n';
  }
  log += 'JWS の検証する\n';
  const valid = await jws.validate(verifyKeys);
  allGreen &&= valid;
  log += 'Produce and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
  const output = data.output;
  if (output.compact) {
    const jws = JWS.deserialize(output.compact);
    const valid = await jws.validate(verifyKeys);
    allGreen &&= valid;
    log += 'Deserialize Compact and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
  }
  if (output.json) {
    const jws = JWS.deserialize(output.json);
    const valid = await jws.validate(verifyKeys);
    allGreen &&= valid;
    log += 'Deserialize JSON and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
  }
  if (output.json_flat) {
    const jws = JWS.deserialize(output.json_flat);
    const valid = await jws.validate(verifyKeys);
    allGreen &&= valid;
    log += 'Deserialize FlattendJSON and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
  }
  return { title, allGreen, log };
}

// --------------------END RFC7520 Section 4 test --------------------
