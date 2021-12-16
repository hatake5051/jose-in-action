export { AGCMKWAlg, isAGCMKWAlg };

/**
 * RFC7518#4.7.  Key Encryption with AES GCM のアルゴリズムを列挙する
 */
type AGCMKWAlg = typeof agcmAlgList[number];
const isAGCMKWAlg = (arg: unknown): arg is AGCMKWAlg =>
  typeof arg === 'string' && agcmAlgList.some((a) => a === arg);
const agcmAlgList = ['A128GCMKW', 'A192GCMKW', 'A256GCMKW'] as const;
