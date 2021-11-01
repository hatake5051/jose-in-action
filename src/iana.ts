// --------------------BEGIN iana constants --------------------

import {
  isJWAMACAlg,
  isJWANoneAlg,
  isJWASigAlg,
  JWAMACAlg,
  JWANoneAlg,
  JWASigAlg,
  ktyFromJWAJWSAlg,
  KtyFromJWAJWSAlg,
} from 'jwa/sec3/alg';
import {
  isJWADEAlg,
  isJWADKAAlg,
  isJWAKAKWAlg,
  isJWAKEAlg,
  isJWAKWAlg,
  JWADEAlg,
  JWADKAAlg,
  JWAKAKWAlg,
  JWAKEAlg,
  JWAKWAlg,
  ktyFromJWAJWEAlg,
  KtyFromJWAJWEAlg,
} from 'jwa/sec4/alg';
import { isJWAEncAlg, JWAEncAlg, KtyFromJWAEncAlg } from 'jwa/sec5/encalg';
import { isJWACrv, isJWAKty, JWACrv, JWAKty } from 'jwa/sec6/kty';
import { JWSJOSEHeader } from 'jws';

export {
  JOSEHeader,
  Alg,
  EncAlg,
  Kty,
  KtyFromAlg,
  ktyFromAlg,
  KeyUse,
  KeyOps,
  Crv,
  isAlg,
  isKty,
  isKeyUse,
  isKeyOps,
  isCrv,
};

/**
 * 暗号操作や使用されるパラメータを表現する JSON オブジェクト
 */
type JOSEHeader<A extends Alg> = A extends JWASigAlg | JWAMACAlg | JWANoneAlg
  ? Partial<JWSJOSEHeader>
  : never;

/**
 * Alg は暗号アルゴリズムを列挙する。
 * RFC7518 に定義されているもののみ今回は実装の対象としている。
 */
type Alg =
  | JWASigAlg
  | JWAMACAlg
  | JWANoneAlg
  | JWAKEAlg
  | JWAKWAlg
  | JWADKAAlg
  | JWAKAKWAlg
  | JWADEAlg
  | EncAlg;
const isAlg = (arg: unknown): arg is Alg =>
  isJWASigAlg(arg) ||
  isJWAMACAlg(arg) ||
  isJWANoneAlg(arg) ||
  isJWAKEAlg(arg) ||
  isJWAKWAlg(arg) ||
  isJWADKAAlg(arg) ||
  isJWAKAKWAlg(arg) ||
  isJWADEAlg(arg) ||
  isEncAlg(arg);

type EncAlg = JWAEncAlg;
const isEncAlg = (arg: unknown): arg is EncAlg => isJWAEncAlg(arg);

/**
 * Kty は JSON Web Key Types を列挙する。
 * 'OKP' は未実装である。
 */
type Kty = JWAKty;
const isKty = (arg: unknown): arg is Kty => isJWAKty(arg);

type KtyFromAlg<A extends Alg> = A extends JWASigAlg | JWAMACAlg | JWANoneAlg
  ? KtyFromJWAJWSAlg<A>
  : A extends JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg
  ? KtyFromJWAJWEAlg<A>
  : A extends JWAEncAlg
  ? KtyFromJWAEncAlg
  : never;

function ktyFromAlg<A extends Alg>(alg: A): KtyFromAlg<A> {
  if (isJWASigAlg(alg) || isJWAMACAlg(alg) || isJWANoneAlg(alg)) {
    return ktyFromJWAJWSAlg(alg) as KtyFromAlg<A>;
  }
  if (
    isJWAKEAlg(alg) ||
    isJWAKWAlg(alg) ||
    isJWADKAAlg(alg) ||
    isJWAKAKWAlg(alg) ||
    isJWADEAlg(alg)
  ) {
    return ktyFromJWAJWEAlg(alg) as KtyFromAlg<A>;
  }
  if (isEncAlg(alg)) {
    return 'oct' as KtyFromAlg<A>;
  }
  throw new TypeError(`${alg} に対応する鍵の kty がわからなかった`);
}

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
