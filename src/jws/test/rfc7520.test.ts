import { exportPublicKey, isJWK, JWKSet } from 'jwk';
import { UTF8 } from 'utility';
import { equalsJWSFlattenedJSONSerialization, equalsJWSJSONSerialization, JWS } from '..';
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
  // 生成
  const jws = await JWS.produce(keys, payload, header);

  // 検証の準備
  const verifyKeys: JWKSet = {
    keys: keys.keys.map((k) => {
      if (isJWK<'oct'>(k, 'oct')) return k;
      if (isJWK<'EC' | 'RSA', 'Priv'>(k, k.kty)) return exportPublicKey(k);
      throw TypeError(`JWK ではない鍵が紛れ込んでいる $key`);
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
      const same = equalsJWSJSONSerialization(output.json, json);
      allGreen &&= same;
      log += 'JSON: ' + (same ? '(OK) ' : 'X ');
    }
    if (output.json_flat) {
      const flat = jws.serialize('json-flat');
      const same = equalsJWSFlattenedJSONSerialization(output.json_flat, flat);
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
