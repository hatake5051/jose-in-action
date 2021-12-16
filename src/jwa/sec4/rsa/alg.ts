export { RSA1_5Alg, isRSA1_5Alg, RSAOAEPAlg, isRSAOAEPAlg };

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
