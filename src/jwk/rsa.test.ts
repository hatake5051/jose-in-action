import { isCommonJWKParams } from './common';
import { isRSAPrivateKey, isRSAPublicKey } from './rsa';

async function test(): Promise<{ log: string; allGreen: boolean }> {
  const baseURL =
    'https://raw.githubusercontent.com/ietf-jose/cookbook/master/jwk/';
  const urlList = [
    '3_1.ec_public_key.json',
    '3_2.ec_private_key.json',
    '3_3.rsa_public_key.json',
    '3_4.rsa_private_key.json',
    '3_5.symmetric_key_mac_computation.json',
    '3_6.symmetric_key_encryption.json',
  ];

  const fetchData = async (path: string): Promise<unknown> =>
    await (await fetch(baseURL + path)).json();
  let allGreen = true;
  let log = 'RSA鍵かどうか判定します。\n';
  for (const path of urlList) {
    log += `TEST NAME: ${path}: `;
    const data = await fetchData(path);
    if (!path.includes('rsa')) {
      if (!isCommonJWKParams(data)) {
        log += 'JWK鍵と判定できていない\n';
        allGreen = false;
      } else if (isRSAPublicKey(data) || isRSAPrivateKey(data)) {
        log += 'RSA鍵ではないはずが、RSA鍵だと識別されている。\n';
        allGreen = false;
      } else {
        log += 'RSA鍵ではないと判定できた(OK)\n';
      }
    } else if (path === '3_3.rsa_public_key.json') {
      if (!isRSAPublicKey(data)) {
        console.log(data);
        log += 'RSA公開鍵の判定に失敗。\n';
        allGreen = false;
      } else {
        log += 'RSA公開鍵と判定できた(OK)\n';
      }
      continue;
    } else if (path === '3_4.rsa_private_key.json') {
      if (!isRSAPrivateKey(data)) {
        log += 'RSA秘密鍵の判定に失敗。\n';
        allGreen = false;
      } else {
        log += 'RSA秘密鍵と判定できた(OK)\n';
      }
    } else {
      log += '想定していないテストケース';
      allGreen = false;
    }
  }
  return { log, allGreen };
}

export { test };
