/**
 * Kty は JSON Web Key Types を列挙する。
 * 'OKP' は未実装である。
 */
type Kty = 'EC' | 'RSA' | 'oct';

/**
 * KeyUse は JSON Web Key Use を列挙する。
 */
type KeyUse = 'sig' | 'enc';

/**
 * JSON Web Key Operations を列挙する。
 */
type KeyOps = 'sign' | 'verify' | 'encrypt' | 'decrypt' | 'wrapKey' | 'unwrapKey' | 'deriveKey' | 'deriveBits';

export { Kty, KeyUse, KeyOps };
