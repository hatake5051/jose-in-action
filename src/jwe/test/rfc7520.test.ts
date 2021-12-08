import {
  equalsJWEFlattenedJSONSerialization,
  equalsJWEJSONSerialization,
  JWE,
  JWEPerRecipientUnprotectedHeader,
} from 'jwe';
import { exportPublicKey, isJWK, JWK, JWKSet } from 'jwk';
import { BASE64URL, BASE64URL_DECODE, UTF8, UTF8_DECODE } from 'utility';
import { fetchData } from './rfc7520.5.test';

export { test };

async function test(path: string): Promise<{
  title: string;
  log: string;
  allGreen: boolean;
}> {
  const data = await fetchData(path);
  let allGreen = true;
  const title = 'RFC7520#5 TEST NAME: ' + data.title;
  let log = '';
  // 準備
  const plaintext = UTF8(data.input.plaintext);
  const header = {
    p: data.encrypting_content.protected,
    su: data.encrypting_content.unprotected,
    ru: Array.isArray(data.encrypting_key)
      ? data.encrypting_key
          .filter((k): k is { header: JWEPerRecipientUnprotectedHeader } => k.header != null)
          .map((k) => k.header)
      : data.encrypting_key?.header,
  };
  const iv = BASE64URL_DECODE(data.generated.iv);
  const aad = data.input.aad ? UTF8(data.input.aad) : undefined;
  type epkObj = { epk: JWK<'EC', 'Priv'> };
  const options = {
    cek: data.generated.cek ? BASE64URL_DECODE(data.generated.cek) : undefined,
    eprivk: Array.isArray(data.encrypting_key)
      ? data.encrypting_key.filter((k): k is epkObj => k.epk != null).map((k) => k.epk)
      : data.encrypting_key?.epk,
  };
  const keys: JWKSet = {
    keys: data.input.key
      ? Array.isArray(data.input.key)
        ? data.input.key
        : [data.input.key]
      : data.input.pwd
      ? [{ kty: 'oct', k: BASE64URL(UTF8(data.input.pwd)) }]
      : [],
  };
  // 暗号文送信者用の鍵準備
  const encKeys: JWKSet = {
    keys: keys.keys.map((k) => {
      if (isJWK<'oct'>(k, 'oct')) return k;
      if (isJWK<'EC' | 'RSA', 'Priv'>(k, k.kty)) return exportPublicKey(k);
      throw TypeError(`JWK ではない鍵が紛れ込んでいる $key`);
    }),
  };
  // JWE 生成
  const jwe = await JWE.enc(encKeys, plaintext, header, iv, aad, options);

  if (data.reproducible) {
    log += 'テストには再現性があるため、シリアライズした結果を比較する\n';
    if (data.output.compact) {
      const compact = jwe.serialize('compact');
      const same = data.output.compact === compact;
      allGreen &&= same;
      log += 'Compact: ' + (same ? '(OK) ' : 'X ');
    }
    if (data.output.json) {
      const json = jwe.serialize('json');
      const same = equalsJWEJSONSerialization(data.output.json, json);
      allGreen &&= same;
      log += 'JSON: ' + (same ? '(OK) ' : 'X ');
    }
    if (data.output.json_flat) {
      const flat = jwe.serialize('json-flat');
      const same = equalsJWEFlattenedJSONSerialization(data.output.json_flat, flat);
      allGreen &&= same;
      log += 'FlattenedJSON: ' + (same ? '(OK) ' : 'X ');
    }
    log += '\n';
  } else {
    log += 'テストには再現性がない (e.g. 署名アルゴリズムに乱数がからむ)\n';
  }
  log += 'JWE の復号を行う\n';
  for (const key of keys.keys) {
    const keysOfOne: JWKSet = { keys: [key] };
    log += `Key(${key.kty}, ${key.kid}) で復号`;
    try {
      const decryptedtext = await jwe.dec(keysOfOne);
      const valid = UTF8_DECODE(decryptedtext) === UTF8_DECODE(plaintext);
      allGreen &&= valid;
      log += 'Encrypt and Decrypt JWE ' + (valid ? '(OK)' : '(X)') + '\n';
    } catch (err) {
      allGreen = false;
      console.log(err);
      log += 'Encrypt and Decrypt JWE (X)\n';
    }
    if (data.output.compact) {
      const jwe = JWE.deserialize(data.output.compact);
      try {
        const decryptedtext = await jwe.dec(keysOfOne);
        const valid = UTF8_DECODE(decryptedtext) === UTF8_DECODE(plaintext);
        allGreen &&= valid;
        log += 'Deserialize Compact and Decrypt JWE ' + (valid ? '(OK)' : '(X)') + '\n';
      } catch (err) {
        allGreen = false;
        console.log(err);
        log += 'Deserialize Compact and Decrypt JWE (X)\n';
      }
    }
    if (data.output.json) {
      const jwe = JWE.deserialize(data.output.json);
      try {
        const decryptedtext = await jwe.dec(keysOfOne);
        const valid = UTF8_DECODE(decryptedtext) === UTF8_DECODE(plaintext);
        allGreen &&= valid;
        log += 'Deserialize JSON and Decrypt JWE ' + (valid ? '(OK)' : '(X)') + '\n';
      } catch (err) {
        allGreen = false;
        console.log(err);
        log += 'Deserialize JSON and Decrypt JWE (X)\n';
      }
    }
    if (data.output.json_flat) {
      const jwe = JWE.deserialize(data.output.json_flat);
      try {
        const decryptedtext = await jwe.dec(keysOfOne);
        const valid = UTF8_DECODE(decryptedtext) === UTF8_DECODE(plaintext);
        allGreen &&= valid;
        log += 'Deserialize Flattened JSON and Decrypt JWE ' + (valid ? '(OK)' : '(X)') + '\n';
      } catch (err) {
        allGreen = false;
        console.log(err);
        log += 'Deserialize Flattened JSON and Decrypt JWE (X)\n';
      }
    }
  }
  return { title, allGreen, log };
}
