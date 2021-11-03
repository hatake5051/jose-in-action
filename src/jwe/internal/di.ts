import {
  isJWAAlgSpecificJOSEHeader,
  isJWADEAlg,
  isJWADKAAlg,
  isJWAKAKWAlg,
  isJWAKEAlg,
  isJWAKWAlg,
  JWAAlgSpecificJOSEHeader,
  JWADEAlg,
  JWADKAAlg,
  JWAKAKWAlg,
  JWAKEAlg,
  JWAKWAlg,
  keyMgmtModeFromJWAAlg,
  newJWADirectAgreementer,
  newJWADirectEncryptor,
  newJWAKeyAgreementerWithKeyWrapping,
  newJWAKeyEncryptor,
  newJWAKeyWrapper,
} from 'jwa/sec4/alg';
import { isJWAEncAlg, JWAEncAlg, newJWAEncOperator } from 'jwa/sec5/encalg';
import {
  DirectEncryptor,
  DirectKeyAgreementer,
  EncOperator,
  KeyAgreementerWithKeyWrapping,
  KeyEncryptor,
  KeyMgmtMode,
  KeyWrapper,
} from 'jwe/ineterface';
import { isObject } from 'utility';

export {
  JWEAlg,
  isJWEAlg,
  keyMgmtModeFromAlg,
  JWEAlgFromKeyMgmtMode,
  JWEEnc,
  isJWEEnc,
  JWEKEAlg,
  isJWEKEAlg,
  newKeyEncryptor,
  JWEKWAlg,
  isJWEKWAlg,
  newKeyWrappaer,
  JWEDKAAlg,
  isJWEDKAAlg,
  newDirectKeyAgreementer,
  JWEKAKWAlg,
  isJWEKAKWAlg,
  newKeyAgreementerWithKeyWrapping,
  JWEDEAlg,
  isJWEDEAlg,
  newDirectEncrytor,
  JWEEncAlg,
  isJWEEncAlg,
  newEncOperator,
  AlgSpecificJOSEHeader,
  isAlgSpecificJOSEHeader,
};

type JWEAlg = JWEKEAlg | JWEKWAlg | JWEDKAAlg | JWEKAKWAlg | JWEDEAlg;

const isJWEAlg = (arg: unknown): arg is JWEAlg =>
  isJWEKEAlg(arg) || isJWEKWAlg(arg) || isJWEDKAAlg(arg) || isJWEKAKWAlg(arg) || isJWEDEAlg(arg);

function keyMgmtModeFromAlg(alg: JWEAlg): KeyMgmtMode {
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

type JWEAlgFromKeyMgmtMode<M extends KeyMgmtMode> = M extends 'KE'
  ? JWEKEAlg
  : M extends 'KW'
  ? JWEKWAlg
  : M extends 'DKA'
  ? JWEDKAAlg
  : M extends 'KAKW'
  ? JWEKAKWAlg
  : M extends 'DE'
  ? JWEDEAlg
  : never;

type JWEEnc = JWEEncAlg;

const isJWEEnc = (arg: unknown): arg is JWEEnc => isJWEEncAlg(arg);

type JWEKEAlg = JWAKEAlg;

const isJWEKEAlg = (arg: unknown): arg is JWEKEAlg => isJWAKEAlg(arg);

function newKeyEncryptor<A extends JWEKEAlg>(alg: A): KeyEncryptor<A> {
  if (isJWAKEAlg(alg)) return newJWAKeyEncryptor(alg) as KeyEncryptor<A>;
  throw new TypeError(`KeyEncryptor<${alg}> は実装されていない`);
}

type JWEKWAlg = JWAKWAlg;

const isJWEKWAlg = (arg: unknown): arg is JWEKWAlg => isJWAKWAlg(arg);

function newKeyWrappaer<A extends JWEKWAlg>(alg: A): KeyWrapper<A> {
  if (isJWAKWAlg(alg)) return newJWAKeyWrapper(alg) as KeyWrapper<A>;
  throw new TypeError(`KeyWrapper<${alg}> は実装されていない`);
}

type JWEDKAAlg = JWADKAAlg;

const isJWEDKAAlg = (arg: unknown): arg is JWEDKAAlg => isJWADKAAlg(arg);

function newDirectKeyAgreementer<A extends JWEDKAAlg>(alg: A): DirectKeyAgreementer<A> {
  if (isJWADKAAlg(alg)) return newJWADirectAgreementer(alg) as DirectKeyAgreementer<A>;
  throw new TypeError(`DirectKeyAgreementer<${alg}> は実装されていない`);
}

type JWEKAKWAlg = JWAKAKWAlg;

const isJWEKAKWAlg = (arg: unknown): arg is JWEKAKWAlg => isJWAKAKWAlg(arg);

function newKeyAgreementerWithKeyWrapping<A extends JWEKAKWAlg>(
  alg: A
): KeyAgreementerWithKeyWrapping<A> {
  if (isJWAKAKWAlg(alg))
    return newJWAKeyAgreementerWithKeyWrapping(alg) as KeyAgreementerWithKeyWrapping<A>;
  throw new TypeError(`KeyAgreementerWithKeyWrapping<${alg}> は実装されていない`);
}

type JWEDEAlg = JWADEAlg;

const isJWEDEAlg = (arg: unknown): arg is JWEDEAlg => isJWADEAlg(arg);

function newDirectEncrytor<A extends JWEDEAlg>(alg: A): DirectEncryptor<A> {
  if (isJWADEAlg(alg)) return newJWADirectEncryptor(alg) as DirectEncryptor<A>;
  throw new TypeError(`DirectEncrypto<${alg}> は実装されていない`);
}

type JWEEncAlg = JWAEncAlg;

const isJWEEncAlg = (arg: unknown): arg is JWEEncAlg => isJWAEncAlg(arg);

function newEncOperator<E extends JWEEncAlg>(enc: E): EncOperator<E> {
  if (isJWAEncAlg(enc)) return newJWAEncOperator(enc) as EncOperator<E>;
  throw new TypeError(`EncOperator<${enc}> は実装されていない`);
}

type AlgSpecificJOSEHeader<A extends JWEKEAlg | JWEKWAlg | JWEDKAAlg | JWEKAKWAlg | JWEDEAlg> =
  A extends JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg
    ? JWAAlgSpecificJOSEHeader<A>
    : Record<string, never>;

const isAlgSpecificJOSEHeader = <A extends JWEKEAlg | JWEKWAlg | JWEDKAAlg | JWEKAKWAlg | JWEDEAlg>(
  arg: unknown
): arg is AlgSpecificJOSEHeader<A> => {
  if (!isObject<{ alg: unknown }>(arg)) return false;
  if (
    isJWAKEAlg(arg.alg) ||
    isJWAKWAlg(arg.alg) ||
    isJWADKAAlg(arg.alg) ||
    isJWAKAKWAlg(arg.alg) ||
    isJWADEAlg(arg.alg)
  )
    return isJWAAlgSpecificJOSEHeader<A>(arg);
  return true;
};
