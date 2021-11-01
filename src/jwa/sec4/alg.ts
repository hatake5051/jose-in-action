import {
  DirectAgreementer,
  DirectEncryptor,
  KeyAgreementerWithKeyWrapping,
  KeyEncryptor,
  KeyWrapper,
} from 'jwe';
import { JWK } from 'jwk';
import { BASE64URL_DECODE } from 'utility';
import { AGCMKeyWrapper, AGCMKWAlg, isAGCMKWAlg } from './aesgcm';
import { AKWAlg, AKWKeyWrapper, isAKWAlg } from './aeskw';
import {
  ECDHDirectAgreementer,
  ECDHKeyAgreementerWithKeyWrapping,
  ECDH_ESAlg,
  ECDH_ESKWAlg,
  isECDH_ESAlg,
  isECDH_ESKWAlg,
} from './ecdh';
import { isPBES2Alg, PBES2Alg, PBES2KeyWrapper } from './pbes2';
import { isRSA1_5Alg, isRSAOAEPAlg, RSA1_5Alg, RSAKeyEncryptor, RSAOAEPAlg } from './rsa';

export {
  JWAKEAlg,
  isJWAKEAlg,
  JWAKWAlg,
  isJWAKWAlg,
  JWADKAAlg,
  isJWADKAAlg,
  JWAKAKWAlg,
  isJWAKAKWAlg,
  JWADEAlg,
  isJWADEAlg,
  KtyFromJWAJWEAlg,
  ktyFromJWAJWEAlg,
  newKeyEncryptor,
  newKeyWrapper,
  newDirectAgreementer,
  newKeyAgreementerWithKeyWrapping,
  newDirectEncryptor,
};

type JWAKEAlg = RSA1_5Alg | RSAOAEPAlg;

const isJWAKEAlg = (arg: unknown): arg is JWAKEAlg => isRSA1_5Alg(arg) || isRSAOAEPAlg(arg);

function newKeyEncryptor<A extends JWAKEAlg>(alg: A): KeyEncryptor<A> {
  if (isRSA1_5Alg(alg) || isRSAOAEPAlg(alg)) return RSAKeyEncryptor as KeyEncryptor<A>;
  throw TypeError(`KeyEncryptor<$alg> は実装されていない`);
}

type JWAKWAlg = AKWAlg | AGCMKWAlg | PBES2Alg;
const isJWAKWAlg = (arg: unknown): arg is JWAKWAlg =>
  isAKWAlg(arg) || isAGCMKWAlg(arg) || isPBES2Alg(arg);

function newKeyWrapper<A extends JWAKWAlg>(alg: A): KeyWrapper<A> {
  if (isAKWAlg(alg)) return AKWKeyWrapper as KeyWrapper<A>;
  if (isAGCMKWAlg(alg)) return AGCMKeyWrapper as KeyWrapper<A>;
  if (isPBES2Alg(alg)) return PBES2KeyWrapper as KeyWrapper<A>;
  throw TypeError(`KeyWrapper<$alg> is not implemented`);
}

type JWADKAAlg = ECDH_ESAlg;
const isJWADKAAlg = (arg: unknown): arg is JWADKAAlg => isECDH_ESAlg(arg);

function newDirectAgreementer<A extends JWADKAAlg>(alg: A): DirectAgreementer<A> {
  if (isECDH_ESAlg(alg)) return ECDHDirectAgreementer as DirectAgreementer<A>;
  throw TypeError(`KeyAgreement<$alg> is not implemented`);
}

type JWAKAKWAlg = ECDH_ESKWAlg;
const isJWAKAKWAlg = (arg: unknown): arg is JWAKAKWAlg => isECDH_ESKWAlg(arg);

function newKeyAgreementerWithKeyWrapping<A extends JWAKAKWAlg>(
  alg: A
): KeyAgreementerWithKeyWrapping<A> {
  if (isECDH_ESKWAlg(alg))
    return ECDHKeyAgreementerWithKeyWrapping as KeyAgreementerWithKeyWrapping<A>;
  throw TypeError(`KeyAgreementerWithKeyWrapping<$alg> is not implemented`);
}

type JWADEAlg = 'dir';
const isJWADEAlg = (arg: unknown): arg is JWADEAlg => typeof arg === 'string' && arg === 'dir';

function newDirectEncryptor<A extends JWADEAlg>(alg: A): DirectEncryptor<A> {
  if (isJWADEAlg(alg))
    return {
      extract: async (alg: A, key: JWK<'oct'>) => BASE64URL_DECODE(key.k),
    } as DirectEncryptor<A>;
  throw TypeError(`DirecyEncryptor<$alg> is not implemented`);
}

type KtyFromJWAJWEAlg<A extends JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg> =
  A extends JWAKEAlg
    ? 'RSA'
    : A extends JWAKWAlg
    ? 'oct'
    : A extends JWADKAAlg | JWAKAKWAlg
    ? 'EC'
    : never;

function ktyFromJWAJWEAlg<A extends JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg>(
  alg: A
): KtyFromJWAJWEAlg<A> {
  if (isJWAKEAlg(alg)) return 'RSA' as KtyFromJWAJWEAlg<A>;
  if (isJWAKWAlg(alg) || isJWADEAlg(alg)) return 'oct' as KtyFromJWAJWEAlg<A>;
  if (isJWADKAAlg(alg) || isJWAKAKWAlg(alg)) return 'EC' as KtyFromJWAJWEAlg<A>;
  throw new TypeError(`${alg} に対応する鍵の kty がわからなかった`);
}
