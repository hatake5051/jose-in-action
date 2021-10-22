/**
 * Kty は JSON Web Key Types を列挙する。
 * 'OKP' は未実装である。
 */
const ktyList = ['EC', 'RSA', 'oct'] as const;
type Kty = typeof ktyList[number];
const isKty = (arg: unknown): arg is Kty => {
  if (typeof arg == 'string') {
    return ktyList.some((k) => k === arg);
  }
  return false;
};
type KtySym = 'oct';
type KtyAsym = 'EC' | 'RSA';

/**
 * KeyUse は JSON Web Key Use を列挙する。
 */
type KeyUse = 'sig' | 'enc';

/**
 * JSON Web Key Operations を列挙する。
 */
type KeyOps =
  | 'sign'
  | 'verify'
  | 'encrypt'
  | 'decrypt'
  | 'wrapKey'
  | 'unwrapKey'
  | 'deriveKey'
  | 'deriveBits';

/**
 * JSON Web Key Elliptic Curve を列挙する。
 * Ed25519, Ed448, X25519, X448, secp256k1 は未実装である。
 */
type Crv = 'P-256' | 'P-384' | 'P-521';

export { Kty, isKty, KtySym, KtyAsym, KeyUse, KeyOps, Crv };
