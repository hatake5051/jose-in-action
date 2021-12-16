export { ESAlg, isESAlg };

/**
 * RFC7518#3.4.  Digital Signature with ECDSA のアルゴリズム識別子を列挙する
 */
type ESAlg = typeof esAlgList[number];

/**
 * 引数が ECDSA アルゴリズム識別子か確認する。
 */
const isESAlg = (arg: unknown): arg is ESAlg =>
  typeof arg === 'string' && esAlgList.some((a) => a === arg);

const esAlgList = ['ES256', 'ES384', 'ES512'] as const;
