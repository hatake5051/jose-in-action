import { JWECEK, JWEEncryptedKey } from 'jwe';
import { KeyEncryptor } from 'jwe/internal/keymgmt';
import { JWK } from 'jwk';
import { BASE64URL_DECODE, CONCAT } from 'utility';

export { RSA1_5Alg, isRSA1_5Alg, RSAOAEPAlg, isRSAOAEPAlg, RSAKeyEncryptor };

const RSAKeyEncryptor: KeyEncryptor<RSA1_5Alg | RSAOAEPAlg> = { enc, dec };

/**
 * RFC7518#4.2.  Key Encryption with RSAES-PKCS1-v1_5 のアルゴリズム識別子を列挙する。
 */
type RSA1_5Alg = 'RSA1_5';
const isRSA1_5Alg = (arg: unknown): arg is RSA1_5Alg => typeof arg === 'string' && arg === 'RSA1_5';

/**
 * RFC7518#4.3.  Key Encryption with RSAES OAEP
 */
type RSAOAEPAlg = typeof rsaoaepAlgList[number];
const isRSAOAEPAlg = (arg: unknown): arg is RSAOAEPAlg =>
  typeof arg === 'string' && rsaoaepAlgList.some((a) => a === arg);
const rsaoaepAlgList = ['RSA-OAEP', 'RSA-OAEP-256'] as const;

/**
 * RSAES-PKCS1-v1_5 か RSA-OAEP アルゴリズム(alg) に従い、与えられた Content Encryption Key を key を使って暗号化する。
 * 計算を行う前に、鍵長が 2048 以上か確認する。
 */
async function enc(
  alg: RSA1_5Alg | RSAOAEPAlg,
  key: JWK<'RSA', 'Pub'>,
  cek: JWECEK
): Promise<JWEEncryptedKey> {
  if (BASE64URL_DECODE(key.n).length * 8 < 2048) {
    // キーサイズが 2048 bit 以上であることが MUST (RFC7518#4.2)
    throw new EvalError(`RSA enc では鍵長が 2048 以上にしてください`);
  }

  if (isRSA1_5Alg(alg)) {
    return await encryptRSA1_5(key, cek);
  } else if (isRSAOAEPAlg(alg)) {
    const hash = alg === 'RSA-OAEP' ? 'SHA-1' : 'SHA-256';
    const keyAlg: RsaHashedImportParams = { name: 'RSA-OAEP', hash };
    const encAlg: RsaOaepParams = { name: 'RSA-OAEP' };
    const k = await window.crypto.subtle.importKey('jwk', key, keyAlg, false, ['encrypt']);
    const e = await window.crypto.subtle.encrypt(encAlg, k, cek);
    return new Uint8Array(e);
  }
  throw new EvalError(`unrecognized alg(${alg})`);
}

async function dec(
  alg: RSA1_5Alg | RSAOAEPAlg,
  key: JWK<'RSA', 'Priv'>,
  ek: JWEEncryptedKey
): Promise<JWECEK> {
  if (BASE64URL_DECODE(key.n).length * 8 < 2048 && BASE64URL_DECODE(key.d).length * 8 < 2048) {
    // キーサイズが 2048 bit 以上であることが MUST (RFC7518#4.2)
    throw new EvalError(`RSA dec では鍵長が 2048 以上にしてください`);
  }

  if (isRSA1_5Alg(alg)) {
    return await decryptRSA1_5(key, ek);
  }
  if (isRSAOAEPAlg(alg)) {
    const hash = alg === 'RSA-OAEP' ? 'SHA-1' : 'SHA-256';
    const keyAlg: RsaHashedImportParams = { name: 'RSA-OAEP', hash };
    const encAlg: RsaOaepParams = { name: 'RSA-OAEP' };
    const k = await window.crypto.subtle.importKey('jwk', key, keyAlg, false, ['decrypt']);
    const e = await window.crypto.subtle.decrypt(encAlg, k, ek);
    return new Uint8Array(e);
  }
  throw EvalError('alg は列挙できているはず');
}

// RFC3447#7.2.1 RSAES-PKCS1-V1_5-ENCRYPT を実装
async function encryptRSA1_5(key: JWK<'RSA', 'Pub'>, message: Uint8Array): Promise<Uint8Array> {
  // k denotes the length in octets of the modulus n
  const k = BASE64URL_DECODE(key.n).length;
  // message to be encrypted, an octet string of length mLen,
  const mLen = message.length;
  // Step1
  if (mLen > k - 11) {
    throw 'message too long';
  }
  // Step2.a
  // const PS = genNonZeroUint8Array(k - mLen - 3);
  // 例示データを複合して PS に使用した値を逆算したもの
  const PS = BASE64URL_DECODE(
    'wx6eRzOkz9TWarNXjlU1eAwOlBN3b7fq9BgksROinirQYwVNNb6GzUMt0fYjbRlEbHdklsK8z1H-L4ZRdgeoPzuE4yNShwteN6hZkofbYRT9iX6kSEYmEs0CRBWUKBeEuFQD4NOGzc5QpfarwLV1U8Djut1l49wr84OH1YaO9X7rn6iclHa_JrgSNWDzITFkr2-X-5uHzDE0HZvvW2v4P8PxS9jbEcsDkROp3KL1NJoEncU5BQk3IB8GghM-kQnIdOdrRmaG0MFHfRs4d1U3OIxK0JjW8xccqpSGlII'
  );
  // Step2.b
  const EM = CONCAT(CONCAT(CONCAT(new Uint8Array([0, 2]), PS), new Uint8Array([0])), message);
  // Step3.a
  const m = OS2IP(EM);
  // Step3.b
  const c = await RSAEP(OS2IP(BASE64URL_DECODE(key.n)), OS2IP(BASE64URL_DECODE(key.e)), m);
  return I2OSP(c, k);
}

async function decryptRSA1_5(key: JWK<'RSA', 'Priv'>, ciphertext: Uint8Array): Promise<Uint8Array> {
  // k is the length in octets of the RSA modulus n
  const k = BASE64URL_DECODE(key.n).length;
  // Step1
  if (ciphertext.length !== k || k < 11) {
    throw 'decryption error';
  }
  // Step2.a
  const c = OS2IP(ciphertext);
  // Step2.b
  let m;
  try {
    m = await RSADP(OS2IP(BASE64URL_DECODE(key.n)), OS2IP(BASE64URL_DECODE(key.d)), c);
  } catch (err) {
    throw 'decryption error';
  }
  // Step2.c
  const EM = I2OSP(m, k);
  // Step3
  if (EM[0] === 0 && EM[1] === 2) {
    let pslen = 0;
    for (let i = 2; i < EM.length; i++) {
      if (EM[i] !== 0) {
        pslen++;
      } else {
        break;
      }
    }
    if (pslen < EM.length - 2 && pslen >= 8) {
      return EM.slice(2 + pslen + 1);
    }
  }
  throw 'decryption error';
}

function genNonZeroUint8Array(len: number): Uint8Array {
  let ans = new Uint8Array(len);
  window.crypto.getRandomValues(ans);
  ans = ans.filter((b) => b !== 0);
  while (ans.length !== len) {
    let append = new Uint8Array(len - ans.length);
    window.crypto.getRandomValues(append);
    append = append.filter((b) => b !== 0);
    ans = CONCAT(ans, append);
  }
  return ans;
}

// RFC3447#4.1 I2OSP
// 整数 x を受け取って長さ xLen のバイナリ列表現を返す
function I2OSP(x: bigint, xLen: number): Uint8Array {
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

// RFC3447#4.2 OS2IP
// バイナリ列 X を受け取って、その非不整数表現を返す
function OS2IP(X: Uint8Array): bigint {
  // Uint8Array を16進表現にする
  const hexStr = Array.from(X)
    .map((e) => {
      let hexchar = e.toString(16);
      if (hexchar.length == 1) {
        hexchar = '0' + hexchar;
      }
      return hexchar;
    })
    .join('');
  return BigInt('0x' + hexStr);
}

// RFC3447#5.1.1 RSA Encryption Primitives
async function RSAEP(n: bigint, e: bigint, m: bigint) {
  if (0n > m || m > n) {
    throw 'message representative out of range';
  }
  return await modPow(m, e, n);
}

// RFC3447#5.1.2 RSA Decryption Primitives
// 一番簡単なやつだけ実装
async function RSADP(n: bigint, d: bigint, c: bigint) {
  if (0n > c || c > n) {
    throw 'ciphertext representative out of range';
  }
  return await modPow(c, d, n);
}

// g を k 乗した値を n で割った余りを返す。 with バイナリ法
async function modPow(g: bigint, k: bigint, n: bigint): Promise<bigint> {
  const k_bin = k.toString(2);
  let r = 1n;
  for (const k of k_bin) {
    r = (r * r) % n;
    if (k == '1') {
      r = (r * g) % n;
    }
  }
  return r;
}
