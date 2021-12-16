import { KeyMgmtMode } from 'jwe/ineterface';
import { AGCMKWAlg, isAGCMKWAlg } from './aesgcm/alg';
import { AKWAlg, isAKWAlg } from './aeskw/alg';
import { ECDH_ESAlg, ECDH_ESKWAlg, isECDH_ESAlg, isECDH_ESKWAlg } from './ecdh/alg';
import { isPBES2Alg, PBES2Alg } from './pbes2/alg';
import { isRSA1_5Alg, isRSAOAEPAlg, RSA1_5Alg, RSAOAEPAlg } from './rsa/alg';

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
  keyMgmtModeFromJWAAlg,
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
    : A extends JWAKWAlg | JWADEAlg
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

function keyMgmtModeFromJWAAlg(
  alg: JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg
): KeyMgmtMode {
  if (isJWAKEAlg(alg)) return 'KE';
  if (isJWAKWAlg(alg)) return 'KW';
  if (isJWADKAAlg(alg)) return 'DKA';
  if (isJWAKAKWAlg(alg)) return 'KAKW';
  if (isJWADEAlg(alg)) return 'DE';
  const a: never = alg;
  throw new TypeError(`${a} の Key Management Mode がわからない`);
}
