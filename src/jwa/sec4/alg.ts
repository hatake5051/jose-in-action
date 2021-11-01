import { AGCMKWAlg, isAGCMKWAlg } from './aesgcm';
import { AKWAlg, isAKWAlg } from './aeskw';
import { ECDH_ESAlg, ECDH_ESKWAlg, isECDH_ESAlg, isECDH_ESKWAlg } from './ecdh';
import { isPBES2Alg, PBES2Alg } from './pbes2';
import { isRSA1_5Alg, isRSAOAEPAlg, RSA1_5Alg, RSAOAEPAlg } from './rsa';

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
};

type JWAKEAlg = RSA1_5Alg | RSAOAEPAlg;

const isJWAKEAlg = (arg: unknown): arg is JWAKEAlg => isRSA1_5Alg(arg) || isRSAOAEPAlg(arg);

type JWAKWAlg = AKWAlg | AGCMKWAlg | PBES2Alg;
const isJWAKWAlg = (arg: unknown): arg is JWAKWAlg =>
  isAKWAlg(arg) || isAGCMKWAlg(arg) || isPBES2Alg(arg);

type JWADKAAlg = ECDH_ESAlg;
const isJWADKAAlg = (arg: unknown): arg is JWADKAAlg => isECDH_ESAlg(arg);

type JWAKAKWAlg = ECDH_ESKWAlg;
const isJWAKAKWAlg = (arg: unknown): arg is JWAKAKWAlg => isECDH_ESKWAlg(arg);

type JWADEAlg = 'dir';
const isJWADEAlg = (arg: unknown): arg is JWADEAlg => typeof arg === 'string' && arg === 'dir';

type KtyFromJWAJWEAlg<A extends JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg> =
  A extends JWAKEAlg
    ? 'RSA'
    : A extends JWAKWAlg
    ? 'oct'
    : A extends JWADKAAlg | JWAKAKWAlg
    ? 'EC'
    : never;
