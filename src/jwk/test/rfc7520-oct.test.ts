import { isJWK, isJWKSym } from '../index';

async function test(): Promise<{
  title: string;
  log: string;
  allGreen: boolean;
}> {
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
  const title = 'RFC7520#3 check symmetry key;';
  let log = '';
  for (const path of urlList) {
    log += `TEST NAME: ${path}: `;
    const data = await fetchData(path);
    if (!path.includes('symmetric_key')) {
      if (!isJWK(data)) {
        log += 'JWK鍵と判定できていない\n';
        allGreen = false;
      } else if (isJWKSym(data)) {
        log += 'oct鍵ではないはずが、oct鍵だと識別されている。\n';
        allGreen = false;
      } else {
        log += 'oct鍵ではないと判定できた(OK)\n';
      }
    } else if (path === '3_5.symmetric_key_mac_computation.json') {
      if (!isJWKSym(data)) {
        console.log(data);
        log += 'oct鍵の判定に失敗。\n';
        allGreen = false;
      } else {
        log += 'oct鍵と判定できた(OK)\n';
      }
      continue;
    } else if (path === '3_6.symmetric_key_encryption.json') {
      if (!isJWKSym(data)) {
        log += 'oct鍵の判定に失敗。\n';
        allGreen = false;
      } else {
        log += 'oct鍵と判定できた(OK)\n';
      }
    } else {
      log += '想定していないテストケース';
      allGreen = false;
    }
  }
  return { title, log, allGreen };
}

export { test };
