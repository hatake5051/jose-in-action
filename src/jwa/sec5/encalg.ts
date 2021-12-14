import { EncOperator } from 'jwe/ineterface';
import { JWECEK } from 'jwe/type';
import { ACBCEnc, ACBCEncOperator, generateCEKForACBCEnc, isACBCEnc } from './acbc';
import { AGCMEnc, AGCMEncOperator, generateCEKForAGCMEnc, isAGCMEnc } from './agcm';

export { JWAEncAlg, isJWAEncAlg, KtyFromJWAEncAlg, generateCEKforJWACEK, newJWAEncOperator };

type JWAEncAlg = ACBCEnc | AGCMEnc;

const isJWAEncAlg = (arg: unknown): arg is JWAEncAlg => isACBCEnc(arg) || isAGCMEnc(arg);

type KtyFromJWAEncAlg = 'oct';

function generateCEKforJWACEK(enc: JWAEncAlg): JWECEK {
  if (isACBCEnc(enc)) return generateCEKForACBCEnc(enc);
  if (isAGCMEnc(enc)) return generateCEKForAGCMEnc(enc);
  throw new TypeError(`${enc} は JWAEncAlg ではない`);
}

function newJWAEncOperator<E extends JWAEncAlg>(enc: E): EncOperator<E> {
  if (isACBCEnc(enc)) return ACBCEncOperator as EncOperator<E>;
  if (isAGCMEnc(enc)) return AGCMEncOperator as EncOperator<E>;
  throw TypeError(`EncOperator<$alg> is not implemented`);
}
