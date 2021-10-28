import { identifyKey, isJWK, JWKSet } from '../../jwk';
import { ASCII, BASE64URL, UTF8 } from '../../util';
import { JWSHeader, JWSJOSEHeader, JWSProtectedHeader, JWSUnprotectedHeader } from './header';
import { isJWSMACAlg, newMacOperator } from './mac';
import {
  deserializeCompact,
  deserializeJSON,
  JWSSerialization,
  SerializationType,
  serializationType,
  serializeCompact,
  serializeJSON,
} from './serialize';
import { isJWSSigAlg, ktyFromJWSSigAlg, newSigOperator } from './sig';
import { JWSHeaderAndSig, JWSPayload, JWSSignature } from './types';

export { JWS };

/**
 * JWS はデジタル署名もしくはメッセージ認証コードで保護されたコンテンツを表現する JSON ベースのデータ構造である。
 */
class JWS {
  private m: JWSPayload;
  private hs: JWSHeaderAndSig | JWSHeaderAndSig[];

  private constructor(m: JWSPayload, hs: JWSHeaderAndSig | JWSHeaderAndSig[]) {
    this.m = m;
    this.hs = hs;
  }

  static async produce(
    keys: JWKSet,
    m: JWSPayload,
    h:
      | { p?: JWSProtectedHeader; u?: JWSUnprotectedHeader }
      | { p?: JWSProtectedHeader; u?: JWSUnprotectedHeader }[]
  ): Promise<JWS> {
    const headerList = Array.isArray(h)
      ? h.map((h) => new JWSHeader(h.p, h.u))
      : [new JWSHeader(h.p, h.u)];
    const hsList = await Promise.all<JWSHeaderAndSig>(
      headerList.map(async (h) => ({ h, s: await sign(keys, m, h) }))
    );
    if (hsList.length === 1) {
      return new JWS(m, hsList[0]);
    }
    return new JWS(m, hsList);
  }

  async validate(keys: JWKSet, isAllValidation = true): Promise<boolean> {
    const hsList = Array.isArray(this.hs) ? this.hs : [this.hs];
    const verifiedList = await Promise.all(
      hsList.map(async (hs) => await verify(keys, this.m, hs))
    );
    return verifiedList.reduce((prev, now) => (isAllValidation ? prev && now : prev || now));
  }

  static deserialize(data: SerializationType): JWS {
    switch (serializationType(data)) {
      case 'compact': {
        const { h, m, s } = deserializeCompact(data as SerializationType<'compact'>);
        return new JWS(m, { h: new JWSHeader(h), s });
      }
      case 'json': {
        const { m, hs } = deserializeJSON(data as SerializationType<'json'>);
        if (hs.length === 1) {
          return new JWS(m, hs[0]);
        }
        return new JWS(m, hs);
      }
      case 'json-flat': {
        const d = data as SerializationType<'json-flat'>;
        const { m, hs } = deserializeJSON({ payload: d.payload, signatures: [d] });
        return new JWS(m, hs[0]);
      }
    }
  }

  serialize<S extends JWSSerialization>(s: S): SerializationType<S> {
    switch (s) {
      case 'compact':
        if (Array.isArray(this.hs)) {
          throw 'JWS Compact Serialization は複数署名を表現できない';
        }
        if (this.hs.h.Protected == null) {
          // つまり this.hs.h.u != null
          throw 'JWS Compact Serialization は JWS Unprotected Header を表現できない';
        }
        if (this.hs.s == null) {
          throw '署名を終えていない';
        }
        return serializeCompact(this.hs.h.Protected, this.m, this.hs.s) as SerializationType<S>;
      case 'json':
        return serializeJSON(this.m, this.hs) as SerializationType<S>;
      case 'json-flat': {
        const json = serializeJSON(this.m, this.hs);
        if (json.signatures.length > 1) {
          throw 'Flattened JWS JSON Serialization は複数署名を表現できない';
        }
        return {
          payload: json.payload,
          signature: json.signatures[0].signature,
          header: json.signatures[0].header,
          protected: json.signatures[0].protected,
        } as SerializationType<S>;
      }
      default:
        throw TypeError(`${s} はJWSSerialization format ではない`);
    }
  }
}

async function sign(keys: JWKSet, m: JWSPayload, h: JWSHeader): Promise<JWSSignature> {
  const jh = h.JOSEHeader;
  const input = jwsinput(m, h.Protected);
  const alg = jh.alg;
  if (jh.alg === 'none') {
    return new Uint8Array();
  } else if (isJWSSigAlg(alg)) {
    const key = identifyKey<typeof alg>(keys, jh as JWSJOSEHeader<typeof alg>);
    if (!isJWK<'EC' | 'RSA', 'Priv'>(key, ktyFromJWSSigAlg(alg), 'Priv'))
      throw new TypeError('公開鍵で署名しようとしている');
    return newSigOperator<typeof alg>(alg).sign(alg, key, input);
  } else if (isJWSMACAlg(alg)) {
    const key = identifyKey<typeof alg>(keys, jh as JWSJOSEHeader<typeof alg>);
    return newMacOperator<typeof alg>(alg).mac(alg, key, input);
  }
  throw new EvalError(`sign(alg: ${alg}) is unimplemented`);
}

async function verify(keys: JWKSet, m: JWSPayload, hs: JWSHeaderAndSig): Promise<boolean> {
  const jh = hs.h.JOSEHeader;
  const alg = jh.alg;
  if (alg === 'none') return true;
  if (hs.s === undefined) return false;
  const input = jwsinput(m, hs.h.Protected);
  if (isJWSSigAlg(alg)) {
    const key = identifyKey<typeof alg>(keys, jh as JWSJOSEHeader<typeof alg>);
    if (!isJWK<'EC' | 'RSA', 'Pub'>(key, ktyFromJWSSigAlg(alg), 'Pub'))
      throw new TypeError('秘密鍵で検証しようとしている');
    return newSigOperator<typeof alg>(alg).verify(alg, key, input, hs.s);
  } else if (isJWSMACAlg(alg)) {
    const key = identifyKey<typeof alg>(keys, jh as JWSJOSEHeader<typeof alg>);
    return newMacOperator<typeof alg>(alg).verify(alg, key, input, hs.s);
  }
  throw new EvalError(`verify(alg: $alg) is unimplemented`);
}

const jwsinput = (m: JWSPayload, p?: JWSProtectedHeader): Uint8Array =>
  ASCII((p !== undefined ? BASE64URL(UTF8(JSON.stringify(p))) : '') + '.' + BASE64URL(m));
