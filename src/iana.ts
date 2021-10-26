// --------------------BEGIN iana constants --------------------

export { Alg, Kty, KeyUse, KeyOps, Crv, isAlg, isKty, isKeyUse, isKeyOps, isCrv };

const algList = [
  'HS256',
  'HS384',
  'HS512',
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'ES512',
  'PS256',
  'PS384',
  'PS512',
  'none',
  'RSA1_5',
  'RSA-OAEP',
  'RSA-OAEP-256',
  'A128KW',
  'A192KW',
  'A256KW',
  'dir',
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A192KW',
  'ECDH-ES+A256KW',
  'A128GCMKW',
  'A192GCMKW',
  'A256GCMKW',
  'PBES2-HS256+A128KW',
  'PBES2-HS384+A192KW',
  'PBES2-HS512+A256KW',
  'A128CBC-HS256',
  'A192CBC-HS384',
  'A256CBC-HS512',
  'A128GCM',
  'A192GCM',
  'A256GCM',
] as const;
/**
 * Alg は暗号アルゴリズムを列挙する。
 * RFC7518 に定義されているもののみ今回は実装の対象としている。
 */
type Alg = typeof algList[number];
const isAlg = (arg: unknown): arg is Alg => {
  if (typeof arg === 'string') {
    return algList.some((a) => a === arg);
  }
  return false;
};

const ktyList = ['EC', 'RSA', 'oct'] as const;
/**
 * Kty は JSON Web Key Types を列挙する。
 * 'OKP' は未実装である。
 */
type Kty = typeof ktyList[number];
const isKty = (arg: unknown): arg is Kty => {
  if (typeof arg == 'string') {
    return ktyList.some((k) => k === arg);
  }
  return false;
};

const keyUseList = ['sig', 'enc'] as const;
/**
 * KeyUse は JSON Web Key Use を列挙する。
 */
type KeyUse = typeof keyUseList[number];
const isKeyUse = (arg: unknown): arg is KeyUse => {
  if (typeof arg === 'string') {
    return keyUseList.some((u) => u === arg);
  }
  return false;
};

/**
 * JSON Web Key Operations を列挙する。
 */
const keyOpsList = [
  'sign',
  'verify',
  'encrypt',
  'decrypt',
  'wrapKey',
  'unwrapKey',
  'deriveKey',
  'deriveBits',
] as const;
type KeyOps = typeof keyOpsList[number];
const isKeyOps = (arg: unknown): arg is KeyOps => {
  if (typeof arg === 'string') {
    return keyOpsList.some((u) => u === arg);
  }
  return false;
};

/**
 * JSON Web Key Elliptic Curve を列挙する。
 * Ed25519, Ed448, X25519, X448, secp256k1 は未実装である。
 */
const crvList = ['P-256', 'P-384', 'P-521'];
type Crv = typeof crvList[number];
const isCrv = (arg: unknown): arg is Crv => {
  if (typeof arg === 'string') {
    return crvList.some((u) => u === arg);
  }
  return false;
};

// --------------------END iana constants --------------------
