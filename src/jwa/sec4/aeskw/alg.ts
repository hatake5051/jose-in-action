export { AKWAlg, isAKWAlg };
/**
 * RFC7518#4.4.  Key Wrapping with AES Key Wrap のアルゴリズムを列挙する。
 */
type AKWAlg = typeof akwAlgList[number];
const isAKWAlg = (arg: unknown): arg is AKWAlg =>
  typeof arg === 'string' && akwAlgList.some((a) => a === arg);
const akwAlgList = ['A128KW', 'A192KW', 'A256KW'] as const;
