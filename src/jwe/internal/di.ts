import { Alg, EncAlg, isEncAlg } from 'iana';
import {
  isJWADEAlg,
  isJWADKAAlg,
  isJWAKAKWAlg,
  isJWAKEAlg,
  isJWAKWAlg,
  keyMgmtModeFromJWAAlg,
  newJWADirectAgreementer,
  newJWADirectEncryptor,
  newJWAKeyAgreementerWithKeyWrapping,
  newJWAKeyEncryptor,
  newJWAKeyWrapper,
} from 'jwa/sec4/alg';
import { generateCEKforJWACEK, isJWAEncAlg, newJWAEncOperator } from 'jwa/sec5/encalg';
import {
  DirectEncryptor,
  DirectKeyAgreementer,
  EncOperator,
  KeyAgreementerWithKeyWrapping,
  KeyEncryptor,
  KeyMgmtMode,
  KeyWrapper,
} from 'jwe/ineterface';
import { JWECEK } from 'jwe/type';

export {
  keyMgmtModeFromAlg,
  generateCEK,
  newKeyEncryptor,
  newKeyWrappaer,
  newDirectKeyAgreementer,
  newKeyAgreementerWithKeyWrapping,
  newDirectEncrytor,
  newEncOperator,
};

function keyMgmtModeFromAlg(alg: Alg<'JWE'>): KeyMgmtMode {
  if (
    isJWAKEAlg(alg) ||
    isJWAKWAlg(alg) ||
    isJWADKAAlg(alg) ||
    isJWAKAKWAlg(alg) ||
    isJWADEAlg(alg)
  )
    return keyMgmtModeFromJWAAlg(alg);
  const a: never = alg;
  throw new TypeError(`${a} の Key Management Mode がわからない`);
}

function generateCEK(enc: EncAlg): JWECEK {
  if (isJWAEncAlg(enc)) return generateCEKforJWACEK(enc);
  throw new TypeError(`${enc} の CEK を生成できない`);
}

function newKeyEncryptor<A extends Alg<'JWE'>>(alg: A): KeyEncryptor<A> {
  if (isJWAKEAlg(alg)) return newJWAKeyEncryptor(alg) as KeyEncryptor<A>;
  throw new TypeError(`KeyEncryptor<${alg}> は実装されていない`);
}

function newKeyWrappaer<A extends Alg<'JWE'>>(alg: A): KeyWrapper<A> {
  if (isJWAKWAlg(alg)) return newJWAKeyWrapper(alg) as KeyWrapper<A>;
  throw new TypeError(`KeyWrapper<${alg}> は実装されていない`);
}

function newDirectKeyAgreementer<A extends Alg<'JWE'>>(alg: A): DirectKeyAgreementer<A> {
  if (isJWADKAAlg(alg)) return newJWADirectAgreementer(alg) as DirectKeyAgreementer<A>;
  throw new TypeError(`DirectKeyAgreementer<${alg}> は実装されていない`);
}

function newKeyAgreementerWithKeyWrapping<A extends Alg<'JWE'>>(
  alg: A
): KeyAgreementerWithKeyWrapping<A> {
  if (isJWAKAKWAlg(alg))
    return newJWAKeyAgreementerWithKeyWrapping(alg) as KeyAgreementerWithKeyWrapping<A>;
  throw new TypeError(`KeyAgreementerWithKeyWrapping<${alg}> は実装されていない`);
}

function newDirectEncrytor<A extends Alg<'JWE'>>(alg: A): DirectEncryptor<A> {
  if (isJWADEAlg(alg)) return newJWADirectEncryptor(alg) as DirectEncryptor<A>;
  throw new TypeError(`DirectEncrypto<${alg}> は実装されていない`);
}

function newEncOperator<E extends EncAlg>(enc: E): EncOperator<E> {
  if (isEncAlg(enc)) return newJWAEncOperator(enc) as EncOperator<E>;
  throw new TypeError(`EncOperator<${enc}> は実装されていない`);
}
