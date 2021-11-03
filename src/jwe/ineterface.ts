import { Alg, JOSEHeader, KtyFromAlg } from 'iana';
import { JWK } from 'jwk';
import { JWEAAD, JWECEK, JWECiphertext, JWEEncryptedKey, JWEIV, JWETag } from './type';

export {
  KeyMgmtMode,
  KeyEncryptor,
  KeyWrapper,
  DirectKeyAgreementer,
  KeyAgreementerWithKeyWrapping,
  DirectEncryptor,
  EncOperator,
};

type KeyMgmtMode = 'KE' | 'KW' | 'DKA' | 'KAKW' | 'DE';

interface KeyEncryptor<A extends Alg> {
  enc: (alg: A, key: JWK<KtyFromAlg<A>, 'Pub'>, cek: JWECEK) => Promise<JWEEncryptedKey>;
  dec: (alg: A, key: JWK<KtyFromAlg<A>, 'Priv'>, ek: JWEEncryptedKey) => Promise<JWECEK>;
}

interface KeyWrapper<A extends Alg> {
  wrap: (key: JWK<KtyFromAlg<A>>, cek: JWECEK, h?: JOSEHeader<A>) => Promise<JWEEncryptedKey>;
  unwrap: (key: JWK<KtyFromAlg<A>>, ek: JWEEncryptedKey, h?: JOSEHeader<A>) => Promise<JWECEK>;
}

interface DirectKeyAgreementer<A extends Alg> {
  partyU: (
    key: JWK<KtyFromAlg<A>, 'Pub'>,
    h: JOSEHeader<A>,
    eprivk: JWK<KtyFromAlg<A>, 'Priv'>
  ) => Promise<JWECEK>;
  partyV: (key: JWK<KtyFromAlg<A>, 'Priv'>, h: JOSEHeader<A>) => Promise<JWECEK>;
}

interface KeyAgreementerWithKeyWrapping<A extends Alg> {
  wrap: (
    key: JWK<KtyFromAlg<A>, 'Pub'>,
    cek: JWECEK,
    h: JOSEHeader<A>,
    eprivk: JWK<KtyFromAlg<A>, 'Priv'>
  ) => Promise<JWEEncryptedKey>;
  unwrap: (
    key: JWK<KtyFromAlg<A>, 'Priv'>,
    ek: JWEEncryptedKey,
    h: JOSEHeader<A>
  ) => Promise<JWECEK>;
}

interface DirectEncryptor<A extends Alg> {
  extract: (alg: A, key: JWK<KtyFromAlg<A>>) => Promise<JWECEK>;
}

interface EncOperator<E extends Alg> {
  enc: (
    enc: E,
    cek: JWECEK,
    iv: JWEIV,
    aad: JWEAAD,
    m: Uint8Array
  ) => Promise<{ c: JWECiphertext; tag: JWETag }>;
  dec: (
    enc: E,
    cek: JWECEK,
    iv: JWEIV,
    aad: JWEAAD,
    c: JWECiphertext,
    tag: JWETag
  ) => Promise<Uint8Array>;
}
