import { Alg, EncAlg, KtyFromAlg } from 'iana/alg';
import { JOSEHeaderParams } from 'iana/header';
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

interface KeyEncryptor<A extends Alg<'JWE'>> {
  enc: (alg: A, key: JWK<KtyFromAlg<A>, 'Pub'>, cek: JWECEK) => Promise<JWEEncryptedKey>;
  dec: (alg: A, key: JWK<KtyFromAlg<A>, 'Priv'>, ek: JWEEncryptedKey) => Promise<JWECEK>;
}

interface KeyWrapper<A extends Alg<'JWE'>> {
  wrap: (
    key: JWK<KtyFromAlg<A>>,
    cek: JWECEK,
    h?: JOSEHeaderParams<'JWE'>
  ) => Promise<{ ek: JWEEncryptedKey; h?: JOSEHeaderParams<'JWE'> }>;
  unwrap: (
    key: JWK<KtyFromAlg<A>>,
    ek: JWEEncryptedKey,
    h?: JOSEHeaderParams<'JWE'>
  ) => Promise<JWECEK>;
}

interface DirectKeyAgreementer<A extends Alg<'JWE'>> {
  partyU: (
    key: JWK<KtyFromAlg<A>, 'Pub'>,
    h: JOSEHeaderParams<'JWE'>,
    eprivk?: JWK<KtyFromAlg<A>, 'Priv'>
  ) => Promise<{ cek: JWECEK; h?: JOSEHeaderParams<'JWE'> }>;
  partyV: (key: JWK<KtyFromAlg<A>, 'Priv'>, h: JOSEHeaderParams<'JWE'>) => Promise<JWECEK>;
}

interface KeyAgreementerWithKeyWrapping<A extends Alg<'JWE'>> {
  wrap: (
    key: JWK<KtyFromAlg<A>, 'Pub'>,
    cek: JWECEK,
    h: JOSEHeaderParams<'JWE'>,
    eprivk?: JWK<KtyFromAlg<A>, 'Priv'>
  ) => Promise<{ ek: JWEEncryptedKey; h?: JOSEHeaderParams<'JWE'> }>;
  unwrap: (
    key: JWK<KtyFromAlg<A>, 'Priv'>,
    ek: JWEEncryptedKey,
    h: JOSEHeaderParams<'JWE'>
  ) => Promise<JWECEK>;
}

interface DirectEncryptor<A extends Alg<'JWE'>> {
  extract: (alg: A, key: JWK<KtyFromAlg<A>>) => Promise<JWECEK>;
}

interface EncOperator<E extends EncAlg> {
  enc: (
    enc: E,
    cek: JWECEK,
    m: Uint8Array,
    aad: JWEAAD,
    iv?: JWEIV
  ) => Promise<{ c: JWECiphertext; tag: JWETag; iv: JWEIV }>;
  dec: (
    enc: E,
    cek: JWECEK,
    iv: JWEIV,
    aad: JWEAAD,
    c: JWECiphertext,
    tag: JWETag
  ) => Promise<Uint8Array>;
}
