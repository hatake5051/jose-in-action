export { HSAlg, isHSAlg };

/**
 * RFC7518#3.2.  HMAC with SHA-2 Functions のアルゴリズム識別子を列挙する。
 */
type HSAlg = typeof hsAlgList[number];

/**
 * 引数が HMAC アルゴリズム識別子か確認する。
 */
const isHSAlg = (arg: unknown): arg is HSAlg =>
  typeof arg === 'string' && hsAlgList.some((a) => a === arg);

const hsAlgList = ['HS256', 'HS384', 'HS512'] as const;
