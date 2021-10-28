// --------------------BEGIN iana constants --------------------

import { isJWAMACAlg, isJWASigAlg, JWAMACAlg, JWASigAlg } from './jwa/sec3/alg';
import { isJWACrv, isJWAKty, JWACrv, JWAKty } from './jwa/sec6/kty';
import { JWSJOSEHeader } from './jws/internal/header';
import { JWSAlg } from './jws/internal/types';

export { JOSEHeader, Alg, Kty, KeyUse, KeyOps, Crv, isAlg, isKty, isKeyUse, isKeyOps, isCrv };

/**
 * 暗号操作や使用されるパラメータを表現する JSON オブジェクト
 */
type JOSEHeader<A extends Alg> = A extends JWSAlg ? Partial<JWSJOSEHeader> : never;

const algList = [
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
type Alg = JWASigAlg | JWAMACAlg | 'none' | typeof algList[number];
const isAlg = (arg: unknown): arg is Alg => {
  if (isJWASigAlg(arg) || isJWAMACAlg(arg)) return true;
  if (typeof arg === 'string') {
    if (arg === 'none') return true;
    return algList.some((a) => a === arg);
  }
  return false;
};

/**
 * Kty は JSON Web Key Types を列挙する。
 * 'OKP' は未実装である。
 */
type Kty = JWAKty;
const isKty = (arg: unknown): arg is Kty => isJWAKty(arg);

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
type Crv = JWACrv;
const isCrv = (arg: unknown): arg is Crv => isJWACrv(arg);

// --------------------END iana constants --------------------
