export { RSAlg, isRSAlg, PSAlg, isPSAlg };

/**
 * RFC7518#3.3.  Digital Signature with RSASSA-PKCS1-v1_5 のアルゴリズム識別子を列挙する。
 */
type RSAlg = typeof rsAlgList[number];

/**
 * 引数が RSA-PKCS1-v1.5 アルゴリズム識別子か確認する。
 */
const isRSAlg = (arg: unknown): arg is RSAlg =>
  typeof arg === 'string' && rsAlgList.some((a) => a === arg);

const rsAlgList = ['RS256', 'RS384', 'RS512'] as const;

/**
 * RFC7518#3.5.  Digital Signature with RSASSA-PSS のアルゴリズム識別子を列挙する。
 */
type PSAlg = typeof psAlgList[number];

/**
 * 引数が RSA-PSS アルゴリズム識別子か確認する。
 */
const isPSAlg = (arg: unknown): arg is PSAlg =>
  typeof arg === 'string' && psAlgList.some((a) => a === arg);

const psAlgList = ['PS256', 'PS384', 'PS512'] as const;
