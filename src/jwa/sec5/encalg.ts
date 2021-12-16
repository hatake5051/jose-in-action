import { ACBCEnc, isACBCEnc } from './acbc/encalg';
import { AGCMEnc, isAGCMEnc } from './agcm/encalg';

export { JWAEncAlg, isJWAEncAlg, KtyFromJWAEncAlg };

type JWAEncAlg = ACBCEnc | AGCMEnc;

const isJWAEncAlg = (arg: unknown): arg is JWAEncAlg => isACBCEnc(arg) || isAGCMEnc(arg);

type KtyFromJWAEncAlg = 'oct';
