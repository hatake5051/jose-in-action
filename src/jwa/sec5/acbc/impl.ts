import { EncOperator } from 'jwe/ineterface';
import { JWEAAD, JWECEK, JWECiphertext, JWEIV, JWETag } from 'jwe/type';
import { BASE64URL, CONCAT } from 'utility';
import { ACBCEnc } from './encalg';

export { ACBCEncOperator, generateCEKForACBCEnc };

/**
 * RFC7518#5.2.  AES_CBC_HMAC_SHA2 Algorithms のアルゴリズムの実装.
 */
const ACBCEncOperator: EncOperator<ACBCEnc> = { enc, dec };

/**
 * RFC7518#5.2.  AES_CBC_HMAC_SHA2 Algorithms のアルゴリズムに従って暗号化する。
 */
async function enc(
  enc: ACBCEnc,
  cek: JWECEK,
  m: Uint8Array,
  aad: JWEAAD,
  iv?: JWEIV
): Promise<{ c: JWECiphertext; tag: JWETag; iv: JWEIV }> {
  const { E, T, IV } = await encryptAES_CBC_HMAC_SHA2(enc, cek, m, aad, iv);
  return { c: E as JWECiphertext, tag: T as JWETag, iv: IV as JWEIV };
}

async function dec(
  enc: ACBCEnc,
  cek: JWECEK,
  iv: JWEIV,
  aad: JWEAAD,
  c: JWECiphertext,
  tag: JWETag
): Promise<Uint8Array> {
  return await decryptAES_CBC_HMAC_SHA2(enc, cek, aad, iv, c, tag);
}

function generateCEKForACBCEnc(enc: ACBCEnc): JWECEK {
  const { MAC_KEY_LEN, ENC_KEY_LEN } = algParams(enc);
  const len = MAC_KEY_LEN + ENC_KEY_LEN;
  const cek = window.crypto.getRandomValues(new Uint8Array(len));
  return cek as JWECEK;
}

/**
 * RFC7518#5.2.2.1 AES_CBC_HMAC_SHA2 Encryption を実装する。
 */
async function encryptAES_CBC_HMAC_SHA2(
  enc: ACBCEnc,
  K: Uint8Array,
  P: Uint8Array,
  A: Uint8Array,
  IV?: Uint8Array
): Promise<{ E: Uint8Array; T: Uint8Array; IV: Uint8Array }> {
  // Step1 enc に基づいて鍵長のチェックを行い、HMAC 計算用の鍵と 暗号化鍵を用意する。
  const { MAC_KEY_LEN, ENC_KEY_LEN, HASH_ALG, T_LEN } = algParams(enc);
  if (K.length !== MAC_KEY_LEN + ENC_KEY_LEN) {
    throw 'K の長さが不一致';
  }
  const MAC_KEY = K.slice(0, MAC_KEY_LEN);
  const ENC_KEY = K.slice(ENC_KEY_LEN);
  // Step2 IV を用意する
  if (!IV) {
    IV = new Uint8Array(16);
    window.crypto.getRandomValues(IV);
  }
  // Step3 AES-CBC で暗号化する。
  const acKey = await window.crypto.subtle.importKey('raw', ENC_KEY, { name: 'AES-CBC' }, false, [
    'encrypt',
  ]);
  const E = new Uint8Array(
    await window.crypto.subtle.encrypt({ name: 'AES-CBC', iv: IV }, acKey, P)
  );
  // Step4
  const AL = intToOctets(A.length * 8, 64 / 8);
  // Step5 HMAC で認証タグを生成する。
  const hKey = await window.crypto.subtle.importKey(
    'raw',
    MAC_KEY,
    { name: 'HMAC', hash: HASH_ALG },
    false,
    ['sign']
  );
  const hSig = await window.crypto.subtle.sign('HMAC', hKey, CONCAT(CONCAT(CONCAT(A, IV), E), AL));
  const T = new Uint8Array(hSig).slice(0, T_LEN);
  return { E, T, IV };
}

/**
 * RFC7518#5.2.2.2 AES_BC_HMAC_SHA2 Decryption を実装する。
 */
async function decryptAES_CBC_HMAC_SHA2(
  enc: ACBCEnc,
  K: Uint8Array,
  A: Uint8Array,
  IV: Uint8Array,
  E: Uint8Array,
  T: Uint8Array
): Promise<Uint8Array> {
  // Step1
  const { MAC_KEY_LEN, ENC_KEY_LEN, HASH_ALG, T_LEN } = algParams(enc);
  if (K.length != MAC_KEY_LEN + ENC_KEY_LEN) {
    throw 'K の長さが不一致';
  }
  const MAC_KEY = K.slice(0, MAC_KEY_LEN);
  const ENC_KEY = K.slice(ENC_KEY_LEN);
  // Step2
  const AL = intToOctets(A.length * 8, 64 / 8);
  // verify としたいところだが、 HMAC の結果をそのまま署名の値とはしていないので
  const hKey = await window.crypto.subtle.importKey(
    'raw',
    MAC_KEY,
    { name: 'HMAC', hash: HASH_ALG },
    false,
    ['sign']
  );
  const hSig = await window.crypto.subtle.sign('HMAC', hKey, CONCAT(CONCAT(CONCAT(A, IV), E), AL));
  const dervivedT = new Uint8Array(hSig).slice(0, T_LEN);
  // 配列の比較がめんどくさいので文字列に直して比較した
  if (BASE64URL(dervivedT) !== BASE64URL(T)) {
    throw 'decryption failed';
  }
  // Step3
  const acKey = await window.crypto.subtle.importKey('raw', ENC_KEY, { name: 'AES-CBC' }, false, [
    'decrypt',
  ]);
  const acDec = await window.crypto.subtle.decrypt({ name: 'AES-CBC', iv: IV }, acKey, E);
  const P = new Uint8Array(acDec);
  return P;
}

function algParams(enc: ACBCEnc) {
  switch (enc) {
    case 'A128CBC-HS256':
      return {
        MAC_KEY_LEN: 16,
        ENC_KEY_LEN: 16,
        HASH_ALG: 'SHA-256',
        T_LEN: 16,
      };
    case 'A192CBC-HS384':
      return {
        MAC_KEY_LEN: 24,
        ENC_KEY_LEN: 24,
        HASH_ALG: 'SHA-384',
        T_LEN: 24,
      };
    case 'A256CBC-HS512':
      return {
        MAC_KEY_LEN: 32,
        ENC_KEY_LEN: 32,
        HASH_ALG: 'SHA-512',
        T_LEN: 32,
      };
  }
}

function intToOctets(x: number, xLen: number): Uint8Array {
  let xStr = x.toString(16);
  if (xStr.length % 2 == 1) {
    xStr = '0' + xStr;
  }
  if (xStr.length / 2 > xLen) {
    throw 'integer too long';
  }
  if (xStr.length / 2 < xLen) {
    xStr = '00'.repeat(xLen - xStr.length / 2) + xStr;
  }
  const ans = new Uint8Array(xLen);
  for (let i = 0; i < xLen; i++) {
    ans[i] = parseInt(xStr.substr(i * 2, 2), 16);
  }
  return ans;
}
