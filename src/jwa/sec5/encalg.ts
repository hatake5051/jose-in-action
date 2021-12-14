import { EncOperator } from 'jwe/ineterface';
import { ACBCEnc, ACBCEncOperator, isACBCEnc } from './acbc';
import { AGCMEnc, AGCMEncOperator, isAGCMEnc } from './agcm';

export { JWAEncAlg, isJWAEncAlg, KtyFromJWAEncAlg, newJWAEncOperator };

type JWAEncAlg = ACBCEnc | AGCMEnc;

const isJWAEncAlg = (arg: unknown): arg is JWAEncAlg => isACBCEnc(arg) || isAGCMEnc(arg);

type KtyFromJWAEncAlg = 'oct';

function newJWAEncOperator<E extends JWAEncAlg>(enc: E): EncOperator<E> {
  if (isACBCEnc(enc)) return ACBCEncOperator as EncOperator<E>;
  if (isAGCMEnc(enc)) return AGCMEncOperator as EncOperator<E>;
  throw TypeError(`EncOperator<$alg> is not implemented`);
}