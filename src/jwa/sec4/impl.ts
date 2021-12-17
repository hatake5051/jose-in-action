import {
  DirectEncryptor,
  DirectKeyAgreementer,
  KeyAgreementerWithKeyWrapping,
  KeyEncryptor,
  KeyWrapper,
} from 'jwe/ineterface';
import { JWECEK } from 'jwe/type';
import { JWK } from 'jwk';
import { BASE64URL_DECODE } from 'utility';
import { isAGCMKWAlg } from './aesgcm/alg';
import { AGCMKeyWrapper } from './aesgcm/impl';
import { isAKWAlg } from './aeskw/alg';
import { AKWKeyWrapper } from './aeskw/impl';
import { isJWAJWEAlg, JWAJWEAlg } from './alg';
import { isECDH_ESAlg, isECDH_ESKWAlg } from './ecdh/alg';
import { ECDHDirectKeyAgreementer, ECDHKeyAgreementerWithKeyWrapping } from './ecdh/impl';
import { isPBES2Alg } from './pbes2/alg';
import { PBES2KeyWrapper } from './pbes2/impl';
import { isRSA1_5Alg, isRSAOAEPAlg } from './rsa/alg';
import { RSAKeyEncryptor } from './rsa/rsa';

export {
  newJWAKeyEncryptor,
  newJWAKeyWrapper,
  newJWADirectAgreementer,
  newJWAKeyAgreementerWithKeyWrapping,
  newJWADirectEncryptor,
};

function newJWAKeyEncryptor<A extends JWAJWEAlg<'KE'>>(alg: A): KeyEncryptor<A> {
  if (isRSA1_5Alg(alg) || isRSAOAEPAlg(alg)) return RSAKeyEncryptor as KeyEncryptor<A>;
  throw TypeError(`KeyEncryptor<$alg> は実装されていない`);
}

function newJWAKeyWrapper<A extends JWAJWEAlg<'KW'>>(alg: A): KeyWrapper<A> {
  if (isAKWAlg(alg)) return AKWKeyWrapper as KeyWrapper<A>;
  if (isAGCMKWAlg(alg)) return AGCMKeyWrapper as KeyWrapper<A>;
  if (isPBES2Alg(alg)) return PBES2KeyWrapper as KeyWrapper<A>;
  throw TypeError(`KeyWrapper<$alg> is not implemented`);
}

function newJWADirectAgreementer<A extends JWAJWEAlg<'DKA'>>(alg: A): DirectKeyAgreementer<A> {
  if (isECDH_ESAlg(alg)) return ECDHDirectKeyAgreementer as unknown as DirectKeyAgreementer<A>;
  throw TypeError(`KeyAgreement<$alg> is not implemented`);
}

function newJWAKeyAgreementerWithKeyWrapping<A extends JWAJWEAlg<'KAKW'>>(
  alg: A
): KeyAgreementerWithKeyWrapping<A> {
  if (isECDH_ESKWAlg(alg))
    return ECDHKeyAgreementerWithKeyWrapping as unknown as KeyAgreementerWithKeyWrapping<A>;
  throw TypeError(`KeyAgreementerWithKeyWrapping<$alg> is not implemented`);
}

function newJWADirectEncryptor<A extends JWAJWEAlg<'DE'>>(alg: A): DirectEncryptor<A> {
  if (isJWAJWEAlg(alg, 'DE'))
    return {
      extract: async (alg: A, key: JWK<'oct'>) => BASE64URL_DECODE(key.k) as JWECEK,
    } as DirectEncryptor<A>;
  throw TypeError(`DirecyEncryptor<$alg> is not implemented`);
}
