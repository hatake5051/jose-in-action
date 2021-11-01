import { JOSEHeader } from 'iana';
import {
  JWADEAlg,
  JWADKAAlg,
  JWAKAKWAlg,
  JWAKEAlg,
  JWAKWAlg,
  KtyFromJWAJWEAlg,
} from 'jwa/sec4/alg';
import { JWECEK, JWEEncryptedKey } from 'jwe';
import { JWK } from 'jwk';

export {
  KeyEncryptor,
  KeyWrapper,
  DirectAgreementer,
  KeyAgreementerWithKeyWrapping,
  DirectEncryptor,
};

type KeyMgmtMode =
  | 'KeyEncryption'
  | 'KeyWrapping'
  | 'DirectKeyAgreement'
  | 'KeyAgreementWithKeyWrapping'
  | 'DirectEncryption';

type JWEAlg = JWEKEAlg | JWEKWAlg | JWEDKAAlg | JWEKAKWAlg | JWEDEAlg;

type JWEKEAlg = JWAKEAlg;

interface KeyEncryptor<A extends JWEKEAlg> {
  enc: (alg: A, key: JWK<KtyFromJWEAlg<A>, 'Pub'>, cek: JWECEK) => Promise<JWEEncryptedKey>;
  dec: (alg: A, key: JWK<KtyFromJWEAlg<A>, 'Priv'>, ek: JWEEncryptedKey) => Promise<JWECEK>;
}

type JWEKWAlg = JWAKWAlg;

interface KeyWrapper<A extends JWEKWAlg> {
  wrap: (key: JWK<KtyFromJWEAlg<A>>, cek: JWECEK, h?: JOSEHeader<A>) => Promise<JWEEncryptedKey>;
  unwrap: (key: JWK<KtyFromJWEAlg<A>>, ek: JWEEncryptedKey, h?: JOSEHeader<A>) => Promise<JWECEK>;
}

type JWEDKAAlg = JWADKAAlg;

interface DirectAgreementer<A extends JWEDKAAlg> {
  partyU: (
    h: JOSEHeader<A>,
    key: JWK<KtyFromJWEAlg<A>, 'Pub'>,
    eprivk: JWK<KtyFromJWEAlg<A>, 'Priv'>
  ) => Promise<JWECEK>;
  partyV: (h: JOSEHeader<A>, key: JWK<KtyFromJWEAlg<A>, 'Priv'>) => Promise<JWECEK>;
}

type JWEKAKWAlg = JWAKAKWAlg;

interface KeyAgreementerWithKeyWrapping<A extends JWEKAKWAlg> {
  wrap: (
    h: JOSEHeader<A>,
    key: JWK<KtyFromJWEAlg<A>, 'Pub'>,
    eprivk: JWK<KtyFromJWEAlg<A>, 'Priv'>,
    cek: JWECEK
  ) => Promise<JWEEncryptedKey>;
  unwrap: (
    h: JOSEHeader<A>,
    key: JWK<KtyFromJWEAlg<A>, 'Priv'>,
    ek: JWEEncryptedKey
  ) => Promise<JWECEK>;
}

type JWEDEAlg = JWADEAlg;

interface DirectEncryptor<A extends JWEDEAlg> {
  extract: (alg: A, key: JWK<KtyFromJWEAlg<A>>) => Promise<JWECEK>;
}

type KtyFromJWEAlg<A extends JWEAlg = JWEAlg> = A extends
  | JWAKEAlg
  | JWAKWAlg
  | JWADKAAlg
  | JWAKAKWAlg
  | JWADEAlg
  ? KtyFromJWAJWEAlg<A>
  : never;
