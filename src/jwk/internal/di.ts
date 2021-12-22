import {
  equalsJWAECPrivKeyParams,
  exportJWAECPubKeyParams,
  isJWAECPrivKeyParams,
  isJWAECPubKeyParams,
  JWAECPrivKeyParams,
  JWAECPubKeyParams,
} from 'jwa/sec6/ec/type';
import { equalsJWAOctKeyParams, isJWAOctKeyParams, JWAOctKeyParams } from 'jwa/sec6/oct';
import {
  equalsJWARSAPubKeyParams,
  exportJWARSAPubKeyParams,
  isJWARSAPrivKeyParams,
  isJWARSAPubKeyParams,
  JWARSAPrivKeyParams,
  JWARSAPubKeyParams,
} from 'jwa/sec6/rsa';

export {
  KeyClass,
  isKeyClass,
  JWKOctParams,
  isJWKOctParams,
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

function equalsJWKRSAParams(l?: Partial<JWKRSAParams>, r?: Partial<JWKRSAParams>): boolean {
  return equalsJWARSAPubKeyParams(l, r);
}

function exportJWKRSAPubParams(priv: JWKRSAParams<'Priv'>): JWKRSAParams<'Pub'> {
  return exportJWARSAPubKeyParams(priv);
}

type JWKECParams<C extends KeyClass = KeyClass> = C extends 'Pub'
  ? JWAECPubKeyParams
  : C extends 'Priv'
  ? JWAECPrivKeyParams
  : never;

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
  return equalsJWAECPrivKeyParams(l, r);
}

function exportJWKECPubParams(priv: JWKECParams<'Priv'>): JWKECParams<'Pub'> {
  return exportJWAECPubKeyParams(priv);
}
