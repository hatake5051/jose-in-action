import { isJWACrv, JWACrv, keylenOfJWACrv } from 'jwa/sec6/ec/crv';

export { Crv, isCrv, keylenOfCrv };

/**
 * JSON Web Key Elliptic Curve を列挙する。
 * Ed25519, Ed448, X25519, X448, secp256k1 は未実装である。
 */
type Crv = JWACrv;
const isCrv = (arg: unknown): arg is Crv => isJWACrv(arg);

function keylenOfCrv(crv: Crv): number {
  if (isJWACrv(crv)) return keylenOfJWACrv(crv);
  throw new TypeError(`this crv name(${crv}) is not implemented`);
}
