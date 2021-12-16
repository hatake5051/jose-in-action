export { ACBCEnc, isACBCEnc };

/**
 * RFC7518#5.2.  AES_CBC_HMAC_SHA2 Algorithms のアルゴリズムを列挙する。
 */
type ACBCEnc = typeof acbcEncList[number];
const isACBCEnc = (arg: unknown): arg is ACBCEnc => acbcEncList.some((a) => a === arg);
const acbcEncList = ['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'] as const;
