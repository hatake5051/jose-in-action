// --------------------BEGIN JWS Serialization definition --------------------
import { BASE64URL, BASE64URL_DECODE, isObject, UTF8, UTF8_DECODE } from 'utility';
import {
  equalsJWSJOSEHeader,
  isJWSUnprotectedHeader,
  JWSHeader,
  JWSProtectedHeader,
  JWSUnprotectedHeader,
} from './header';
import { JWSHeaderAndSig, JWSPayload, JWSSignature } from './types';

export {
  JWSSerialization,
  SerializationType,
  serializationType,
  JWSCompactSerialization,
  JWSJSONSerialization,
  JWSFlattenedJSONSerialization,
  serializeCompact,
  deserializeCompact,
  serializeJSON,
  deserializeJSON,
  equalsJWSJSONSerialization,
  equalsJWSFlattenedJSONSerialization,
  isJWSJSONSerialization,
  isJWSFlattenedJSONSerialization,
};

/**
 * JWS には2つのシリアライぜーションがあり、
 * スペースに制約のある環境向けの compact で url-safe な表現である JWS Compact Serialization と
 * 複数の署名や MAC を１つのコンテンツに適用したものを JSON で表現する JWS JSON Serialization がある。
 * さらに、 JWS JSON Serialization は署名が１つだけの場合に JWS Flattened JSON Serializatino がある。
 */
type JWSSerialization = 'compact' | 'json' | 'json-flat';

/**
 * Serialization の型を表現する。
 */
type SerializationType<S extends JWSSerialization = JWSSerialization> = S extends 'compact'
  ? JWSCompactSerialization
  : S extends 'json'
  ? JWSJSONSerialization
  : S extends 'json-flat'
  ? JWSFlattenedJSONSerialization
  : never;

/**
 * Serialization された JWS のフォーマットが何か判定する
 */
function serializationType(data: unknown): JWSSerialization {
  if (typeof data == 'string') {
    return 'compact';
  }
  if (typeof data == 'object' && data != null) {
    if ('signatures' in data) return 'json';
    return 'json-flat';
  }
  throw TypeError(`${data} は JWSSerialization ではない`);
}

/**
 * JWS を URL-safe な文字列をする serialization
 * 署名は１つだけしか表現できず、 Unprotected Header も表現できない
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * で表現する。
 */
type JWSCompactSerialization = string;

/**
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * に JWS をシリアライズする。
 */
function serializeCompact(
  h: JWSProtectedHeader,
  m: JWSPayload,
  s?: JWSSignature
): JWSCompactSerialization {
  let ans = BASE64URL(UTF8(JSON.stringify(h))) + '.' + BASE64URL(m);
  if (s != null) ans += '.' + BASE64URL(s);
  return ans;
}

/**
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * を JWS にデシリアライズする。
 */
function deserializeCompact(compact: JWSCompactSerialization): {
  h: JWSProtectedHeader;
  m: JWSPayload;
  s: JWSSignature;
} {
  const c = compact.split('.');
  if (c.length !== 3) {
    throw 'JWS Compact Serialization の形式ではない';
  }
  const [header, payload, signature] = c;
  if (header === '') {
    throw 'JWS Compact Serialization では Protected Header が必須';
  }
  return {
    h: JSON.parse(UTF8_DECODE(BASE64URL_DECODE(header))),
    m: BASE64URL_DECODE(payload),
    s: BASE64URL_DECODE(signature),
  };
}

/**
 * JSON で Serialization する
 * コンパクトでもないし、 url-safe でもないが表現に制限はない。
 */
type JWSJSONSerialization = {
  /**
   * BASE64URL(JWS Payload)
   */
  payload: string;
  /**
   * 署名を表現するオブジェクトの配列
   */
  signatures: {
    /**
     * BASE64URL(JWS Signature)
     */
    signature: string;
    /**
     * UNprotected Header があればそのまま JSON でシリアライズ。
     * ないときは存在してはならない。
     */
    header?: JWSUnprotectedHeader;
    /**
     * Protected Header があれば BASE64URL(UTF8(JWS Protected Header)) デシリアライズ。
     * ないときは存在してはならない。
     */
    protected?: string;
  }[];
};

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
        (s.header == null || isJWSUnprotectedHeader(s.header)) &&
        (s.protected == null || typeof s.protected === 'string')
    )
  );
}

function serializeJSON(
  m: JWSPayload,
  hs: JWSHeaderAndSig | JWSHeaderAndSig[]
): JWSJSONSerialization {
  const hsList = Array.isArray(hs) ? hs : [hs];
  return {
    payload: BASE64URL(m),
    signatures: hsList.map((hs) => {
      if (hs.s === undefined) {
        throw '署名を終えていない';
      }
      return {
        signature: BASE64URL(hs.s),
        header: hs.h.Unprotected,
        protected:
          hs.h.Protected !== undefined
            ? BASE64URL(UTF8(JSON.stringify(hs.h.Protected)))
            : undefined,
      };
    }),
  };
}

function deserializeJSON(json: JWSJSONSerialization): {
  m: JWSPayload;
  hs: JWSHeaderAndSig[];
} {
  return {
    m: BASE64URL_DECODE(json.payload),
    hs: json.signatures.map((sig) => ({
      s: BASE64URL_DECODE(sig.signature),
      h: new JWSHeader(
        sig.protected !== undefined
          ? JSON.parse(UTF8_DECODE(BASE64URL_DECODE(sig.protected)))
          : undefined,
        sig.header
      ),
    })),
  };
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
        if (equalsJWSJOSEHeader(ll, rr)) continue;
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

/**
 * 署名が１つだけの時に、JSON serialization は平滑化できる。
 * signatures は存在してはならない。
 */
type JWSFlattenedJSONSerialization = {
  payload: string;
  signature: string;
  header?: JWSUnprotectedHeader;
  protected?: string;
};

function equalsJWSFlattenedJSONSerialization(
  l?: JWSFlattenedJSONSerialization,
  r?: JWSFlattenedJSONSerialization
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  if (l.payload !== r.payload) return false;
  return equalsSignatureInJWSJSONSerialization(l, r);
}

const isJWSFlattenedJSONSerialization = (arg: unknown): arg is JWSFlattenedJSONSerialization =>
  isObject<JWSFlattenedJSONSerialization>(arg) &&
  typeof arg.payload === 'string' &&
  (arg.protected == null || typeof arg.protected === 'string') &&
  typeof arg.signature === 'string' &&
  (arg.header == null || isJWSUnprotectedHeader(arg.header));

// --------------------END JWS Serialization definition --------------------
