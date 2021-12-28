// --------------------BEGIN JWS Serialization definition --------------------

import { equalsJOSEHeaderParams, isJOSEHeaderParams } from 'iana/header';
import {
  JWSCompactSerialization,
  JWSFlattenedJSONSerialization,
  JWSJSONSerialization,
  JWSPayload,
  JWSSignature,
  JWSUnprotectedHeader,
} from 'jws/type';
import { Arrayable, BASE64URL, BASE64URL_DECODE, isObject } from 'utility';

/**
 * JWS には2つのシリアライぜーションがあり、
 * スペースに制約のある環境向けの compact で url-safe な表現である JWS Compact Serialization と
 * 複数の署名や MAC を１つのコンテンツに適用したものを JSON で表現する JWS JSON Serialization がある。
 * さらに、 JWS JSON Serialization は署名が１つだけの場合に JWS Flattened JSON Serializatino がある。
 */
export type JWSSerializationFormat = 'compact' | 'json' | 'json_flat';

/**
 * Serialization の型を表現する。
 */
export type JWSSerialization<S extends JWSSerializationFormat = JWSSerializationFormat> =
  S extends 'compact'
    ? JWSCompactSerialization
    : S extends 'json'
    ? JWSJSONSerialization
    : S extends 'json_flat'
    ? JWSFlattenedJSONSerialization
    : never;

/**
 * Serialization された JWS のフォーマットが何か判定する
 */
export function jwsSerializationFormat(data: unknown): JWSSerializationFormat {
  if (typeof data == 'string') {
    return 'compact';
  }
  if (typeof data == 'object' && data != null) {
    if ('signatures' in data) return 'json';
    return 'json_flat';
  }
  throw TypeError(`${data} は JWSSerialization ではない`);
}

export const JWSCompactSerializer = {
  serialize: serializeCompact,
  deserialize: deserializeCompact,
};

export const JWSJSONSerializer = {
  serialize: serializeJSON,
  deserialize: deserializeJSON,
  is: isJWSJSONSerialization,
  equals: equalsJWSJSONSerialization,
};

export const JWSFlattenedJSONSerializer = {
  serialize: serializeJWSFlattenedJSON,
  deserialize: deserializeJWSFlattenedJSON,
  is: isJWSFlattenedJSONSerialization,
  equals: equalsJWSFlattenedJSONSerialization,
};

/**
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * に JWS をシリアライズする。
 */
function serializeCompact(
  p_b64u: string,
  m: JWSPayload,
  s?: JWSSignature
): JWSCompactSerialization {
  return `${p_b64u}.${BASE64URL(m)}.${s ? BASE64URL(s) : ''}`;
}

/**
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * を JWS にデシリアライズする。
 */
function deserializeCompact(compact: JWSCompactSerialization): {
  p_b64u: string;
  m: JWSPayload;
  s: JWSSignature;
} {
  const c = compact.split('.');

  const [header, payload, signature] = c;
  if (header == null || payload == null || signature == null) {
    throw 'JWS Compact Serialization の形式ではない';
  }
  if (header === '') {
    throw 'JWS Compact Serialization では Protected Header が必須';
  }
  return {
    p_b64u: header,
    m: BASE64URL_DECODE(payload) as JWSPayload,
    s: BASE64URL_DECODE(signature) as JWSSignature,
  };
}

function isJWSJSONSerialization(arg: unknown): arg is JWSJSONSerialization {
  return (
    isObject<JWSJSONSerialization>(arg) &&
    typeof arg.payload === 'string' &&
    Array.isArray(arg.signatures) &&
    arg.signatures.every(
      (s: unknown) =>
        isObject<{
          signature: string;
          header?: JWSUnprotectedHeader;
          protected?: string;
        }>(s) &&
        typeof s.signature === 'string' &&
        (s.header == null || isJOSEHeaderParams(s.header, 'JWS')) &&
        (s.protected == null || typeof s.protected === 'string')
    )
  );
}

function serializeJSON(
  m: JWSPayload,
  hs: Arrayable<{ p_b64u?: string; u?: JWSUnprotectedHeader; sig: JWSSignature }>
): JWSJSONSerialization {
  const hsList = Array.isArray(hs) ? hs : [hs];
  return {
    payload: BASE64URL(m),
    signatures: hsList.map((hs) => {
      return {
        signature: BASE64URL(hs.sig),
        header: hs.u,
        protected: hs.p_b64u,
      };
    }),
  };
}

function deserializeJSON(json: JWSJSONSerialization): {
  m: JWSPayload;
  hs: Arrayable<{ p_b64u?: string; u?: JWSUnprotectedHeader; sig: JWSSignature }>;
} {
  const m = BASE64URL_DECODE(json.payload) as JWSPayload;
  const hslist = json.signatures.map((sig) => ({
    p_b64u: sig.protected,
    u: sig.header,
    sig: BASE64URL_DECODE(sig.signature) as JWSSignature,
  }));
  return { m, hs: hslist[0] && !hslist[1] ? hslist[0] : hslist };
}

function equalsJWSJSONSerialization(l?: JWSJSONSerialization, r?: JWSJSONSerialization): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of ['payload', 'signatures'] as const) {
    const ln = l[n];
    const rn = r[n];
    if (ln == null && rn == null) continue;
    if (ln == null || rn == null) return false;
    if (n === 'payload') {
      if (ln === rn) continue;
      return false;
    } else if (n === 'signatures') {
      const ll = ln as {
        signature: string;
        header?: JWSUnprotectedHeader;
        protected?: string;
      }[];
      const rr = rn as {
        signature: string;
        header?: JWSUnprotectedHeader;
        protected?: string;
      }[];
      if (
        ll.every((l) => rr.some((r) => equalsSignatureInJWSJSONSerialization(l, r))) &&
        rr.every((r) => ll.some((l) => equalsSignatureInJWSJSONSerialization(l, r)))
      )
        continue;
      return false;
    }
  }
  return true;
}

function equalsSignatureInJWSJSONSerialization(
  l?: {
    signature: string;
    header?: JWSUnprotectedHeader;
    protected?: string;
  },
  r?: {
    signature: string;
    header?: JWSUnprotectedHeader;
    protected?: string;
  }
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of ['signature', 'header', 'protected'] as const) {
    const ln = l[n];
    const rn = r[n];
    if (ln == null && rn == null) continue;
    if (ln == null || rn == null) return false;
    switch (n) {
      case 'header': {
        const ll = ln as JWSUnprotectedHeader;
        const rr = rn as JWSUnprotectedHeader;
        if (equalsJOSEHeaderParams(ll, rr)) continue;
        return false;
      }
      case 'protected':
      case 'signature': {
        if (ln === rn) continue;
        return false;
      }
    }
  }
  return true;
}

function serializeJWSFlattenedJSON(
  h: { p_b64u?: string; u?: JWSUnprotectedHeader },
  m: JWSPayload,
  s: JWSSignature
): JWSFlattenedJSONSerialization {
  return {
    payload: BASE64URL(m),
    signature: BASE64URL(s),
    header: h.u,
    protected: h.p_b64u,
  };
}

function deserializeJWSFlattenedJSON(flat: JWSFlattenedJSONSerialization): {
  h: { p_b64u?: string; u?: JWSUnprotectedHeader };
  m: JWSPayload;
  s: JWSSignature;
} {
  return {
    h: { p_b64u: flat.protected, u: flat.header },
    m: BASE64URL_DECODE(flat.payload) as JWSPayload,
    s: BASE64URL_DECODE(flat.signature) as JWSSignature,
  };
}

function equalsJWSFlattenedJSONSerialization(
  l?: JWSFlattenedJSONSerialization,
  r?: JWSFlattenedJSONSerialization
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  if (l.payload !== r.payload) return false;
  return equalsSignatureInJWSJSONSerialization(l, r);
}

function isJWSFlattenedJSONSerialization(arg: unknown): arg is JWSFlattenedJSONSerialization {
  return (
    isObject<JWSFlattenedJSONSerialization>(arg) &&
    typeof arg.payload === 'string' &&
    (arg.protected == null || typeof arg.protected === 'string') &&
    typeof arg.signature === 'string' &&
    (arg.header == null || isJOSEHeaderParams(arg.header, 'JWS'))
  );
}

// --------------------END JWS Serialization definition --------------------
