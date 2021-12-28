import {
  equalsJWAECPrivKeyParams,
  equalsJWAECPubKeyParams,
  exportJWAECPubKeyParams,
  isJWAECPrivKeyParams,
  isJWAECPubKeyParams,
  isPartialJWAECPrivKeyParams,
  isPartialJWAECPubKeyParams,
  JWAECPrivKeyParams,
  JWAECPubKeyParams,
} from 'jwa/sec6/ec/type';
import {
  equalsJWAOctKeyParams,
  isJWAOctKeyParams,
  isPartialJWAOctKeyParams,
  JWAOctKeyParams,
} from 'jwa/sec6/oct';
import {
  equalsJWARSAPrivKeyParams,
  equalsJWARSAPubKeyParams,
  exportJWARSAPubKeyParams,
  isJWARSAPrivKeyParams,
  isJWARSAPubKeyParams,
  isPartialJWARSAPrivKeyParams,
  isPartialJWARSAPubKeyParams,
  JWARSAPrivKeyParams,
  JWARSAPubKeyParams,
} from 'jwa/sec6/rsa';

export {
  KeyClass,
  isKeyClass,
  JWKOctParams,
  isJWKOctParams,
  isPartialJWKOctParams,
  equalsJWKOctParams,
  JWKRSAParams,
  isJWKRSAParams,
  equalsJWKRSAParams,
  exportJWKRSAPubParams,
  JWKECParams,
  isJWKECParams,
  equalsJWKECParams,
  exportJWKECPubParams,
};

type KeyClass = 'Pub' | 'Priv';
const isKeyClass = (arg: unknown): arg is KeyClass => arg === 'Pub' || arg === 'Priv';

type JWKOctParams = JWAOctKeyParams;

function isJWKOctParams(arg: unknown): arg is JWKOctParams {
  return isJWAOctKeyParams(arg);
}

function isPartialJWKOctParams(arg: unknown): arg is Partial<JWKOctParams> {
  return isPartialJWAOctKeyParams(arg);
}

function equalsJWKOctParams(l?: Partial<JWKOctParams>, r?: Partial<JWKOctParams>): boolean {
  return equalsJWAOctKeyParams(l, r);
}

type JWKRSAParams<C extends KeyClass = KeyClass> = C extends 'Pub'
  ? JWARSAPubKeyParams
  : C extends 'Priv'
  ? JWARSAPrivKeyParams
  : never;

function isJWKRSAParams<C extends KeyClass>(arg: unknown, c?: C): arg is JWKRSAParams<C> {
  if (c === 'Pub') {
    return isJWARSAPubKeyParams(arg);
  }
  if (c === 'Priv') {
    return isJWARSAPrivKeyParams(arg);
  }
  return isJWARSAPubKeyParams(arg) || isJWARSAPrivKeyParams(arg);
}

function isPartialJWKRSAParams<C extends KeyClass>(
  arg: unknown,
  c?: C
): arg is Partial<JWKRSAParams<C>> {
  if (c === 'Pub') {
    return isPartialJWARSAPubKeyParams(arg);
  }
  if (c === 'Priv') {
    return isPartialJWARSAPrivKeyParams(arg);
  }
  return isPartialJWARSAPubKeyParams(arg) || isPartialJWARSAPrivKeyParams(arg);
}

function equalsJWKRSAParams(l?: Partial<JWKRSAParams>, r?: Partial<JWKRSAParams>): boolean {
  if (isPartialJWKRSAParams(l, 'Priv')) {
    return isPartialJWKRSAParams(r, 'Priv') && equalsJWARSAPrivKeyParams(l, r);
  }
  if (isPartialJWKRSAParams(l, 'Pub')) {
    return isPartialJWKRSAParams(r, 'Pub') && equalsJWARSAPubKeyParams(l, r);
  }
  return false;
}

function exportJWKRSAPubParams(priv: JWKRSAParams<'Priv'>): JWKRSAParams<'Pub'> {
  return exportJWARSAPubKeyParams(priv);
}

type JWKECParams<C extends KeyClass = KeyClass> = C extends 'Pub'
  ? JWAECPubKeyParams
  : C extends 'Priv'
  ? JWAECPrivKeyParams
  : never;

function isPartialJWKECParams<C extends KeyClass>(
  arg: unknown,
  c?: C
): arg is Partial<JWKECParams<C>> {
  if (c === 'Pub') {
    return isPartialJWAECPubKeyParams(arg);
  }
  if (c === 'Priv') {
    return isPartialJWAECPrivKeyParams(arg);
  }
  return isPartialJWAECPubKeyParams(arg) || isPartialJWAECPrivKeyParams(arg);
}

function isJWKECParams<C extends KeyClass>(arg: unknown, c?: C): arg is JWKECParams<C> {
  if (c === 'Pub') {
    return isJWAECPubKeyParams(arg);
  }
  if (c === 'Priv') {
    return isJWAECPrivKeyParams(arg);
  }
  return isJWAECPubKeyParams(arg) || isJWAECPrivKeyParams(arg);
}

function equalsJWKECParams(l?: Partial<JWKECParams>, r?: Partial<JWKECParams>): boolean {
  if (isPartialJWKECParams(l, 'Priv')) {
    return isPartialJWKECParams(r, 'Priv') && equalsJWAECPrivKeyParams(l, r);
  }
  if (isPartialJWKECParams(l, 'Pub')) {
    return isPartialJWKECParams(r, 'Pub') && equalsJWAECPubKeyParams(l, r);
  }
  return false;
}

function exportJWKECPubParams(priv: JWKECParams<'Priv'>): JWKECParams<'Pub'> {
  return exportJWAECPubKeyParams(priv);
}
