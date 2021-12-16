import { EncOperator } from 'jwe/ineterface';
import { JWECEK } from 'jwe/type';
import { isACBCEnc } from './acbc/encalg';
import { ACBCEncOperator, generateCEKForACBCEnc } from './acbc/impl';
import { AGCMEncOperator, generateCEKForAGCMEnc } from './agcm/agcm';
import { isAGCMEnc } from './agcm/encalg';
import { JWAEncAlg } from './encalg';

export { generateCEKforJWACEK, newJWAEncOperator };

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
