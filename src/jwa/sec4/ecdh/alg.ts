export { ECDH_ESAlg, isECDH_ESAlg, ECDH_ESKWAlg, isECDH_ESKWAlg };

/**
 * RFC7518#4.6 Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
 * ECDH 鍵合意アルゴリズムを列挙する。
 */

/**
 * "enc" アルゴリズムのための Content Encryption Key として直接、鍵合意結果を使うアルゴリズムを列挙。
 * これらはアルゴリズムは鍵管理のうち、 Direct Key Agreement mode である。
 */
type ECDH_ESAlg = 'ECDH-ES';
const isECDH_ESAlg = (arg: unknown): arg is ECDH_ESAlg =>
  typeof arg === 'string' && arg === 'ECDH-ES';

/**
 * "enc" アルゴリズムのための Content Encryption Key を AES Key wrapping するときの対称鍵として
 * 鍵合意結果を使うアルゴリズムを列挙。
 * これらはアルゴリズムは鍵管理のうち、 Key Agreement with Key Wrapping mode である。
 */
type ECDH_ESKWAlg = typeof ecdhEsKwAlgList[number];
const isECDH_ESKWAlg = (arg: unknown): arg is ECDH_ESKWAlg =>
  typeof arg === 'string' && ecdhEsKwAlgList.some((a) => a === arg);

const ecdhEsKwAlgList = ['ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'] as const;
