export { PBES2Alg, isPBES2Alg };
/**
 * RFC7518#4.8.  Key Encryption with PBES2
 */
type PBES2Alg = typeof pbes2AlgList[number];
const isPBES2Alg = (arg: unknown): arg is PBES2Alg =>
  typeof arg === 'string' && pbes2AlgList.some((a) => a === arg);
const pbes2AlgList = ['PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'] as const;
