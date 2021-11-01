import { Alg, JOSEHeader, KtyFromAlg } from 'iana';
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

// type JWEAlg = JWEKEAlg | JWEKWAlg | JWEDKAAlg | JWEKAKWAlg | JWEDEAlg;

// type JWEKEAlg = JWAKEAlg;

interface KeyEncryptor<A extends Alg> {
  enc: (alg: A, key: JWK<KtyFromAlg<A>, 'Pub'>, cek: JWECEK) => Promise<JWEEncryptedKey>;
  dec: (alg: A, key: JWK<KtyFromAlg<A>, 'Priv'>, ek: JWEEncryptedKey) => Promise<JWECEK>;
}

// type JWEKWAlg = JWAKWAlg;

interface KeyWrapper<A extends Alg> {
  wrap: (key: JWK<KtyFromAlg<A>>, cek: JWECEK, h?: JOSEHeader<A>) => Promise<JWEEncryptedKey>;
  unwrap: (key: JWK<KtyFromAlg<A>>, ek: JWEEncryptedKey, h?: JOSEHeader<A>) => Promise<JWECEK>;
}

// type JWEDKAAlg = JWADKAAlg;

interface DirectAgreementer<A extends Alg> {
  partyU: (
    h: JOSEHeader<A>,
    key: JWK<KtyFromAlg<A>, 'Pub'>,
    eprivk: JWK<KtyFromAlg<A>, 'Priv'>
  ) => Promise<JWECEK>;
  partyV: (h: JOSEHeader<A>, key: JWK<KtyFromAlg<A>, 'Priv'>) => Promise<JWECEK>;
}

// type JWEKAKWAlg = JWAKAKWAlg;

interface KeyAgreementerWithKeyWrapping<A extends Alg> {
  wrap: (
    h: JOSEHeader<A>,
    key: JWK<KtyFromAlg<A>, 'Pub'>,
    eprivk: JWK<KtyFromAlg<A>, 'Priv'>,
    cek: JWECEK
  ) => Promise<JWEEncryptedKey>;
  unwrap: (
    h: JOSEHeader<A>,
    key: JWK<KtyFromAlg<A>, 'Priv'>,
    ek: JWEEncryptedKey
  ) => Promise<JWECEK>;
}

// type JWEDEAlg = JWADEAlg;

interface DirectEncryptor<A extends Alg> {
  extract: (alg: A, key: JWK<KtyFromAlg<A>>) => Promise<JWECEK>;
}

// type KtyFromJWEAlg<A extends JWEAlg = JWEAlg> = A extends
//   | JWAKEAlg
//   | JWAKWAlg
//   | JWADKAAlg
//   | JWAKAKWAlg
//   | JWADEAlg
//   ? KtyFromJWAJWEAlg<A>
//   : never;
