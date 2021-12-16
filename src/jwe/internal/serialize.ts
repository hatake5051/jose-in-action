import { equalsJOSEHeader, isJOSEHeader } from 'iana/header';
import {
  JWEAAD,
  JWECiphertext,
  JWECompactSerialization,
  JWEEncryptedKey,
  JWEFlattenedJSONSerialization,
  JWEIV,
  JWEJSONSerialization,
  JWEPerRecipientUnprotectedHeader,
  JWESharedUnprotectedHeader,
  JWETag,
} from 'jwe/type';
import { BASE64URL, BASE64URL_DECODE, isObject } from 'utility';

export type JWESerializationFormat = 'compact' | 'json' | 'json_flat';

export type JWESerialization<S extends JWESerializationFormat = JWESerializationFormat> =
  S extends 'compact'
    ? JWECompactSerialization
    : S extends 'json'
    ? JWEJSONSerialization
    : S extends 'json_flat'
    ? JWEFlattenedJSONSerialization
    : never;

export function jweSerializationFormat(data: unknown): JWESerializationFormat {
  if (typeof data == 'string') {
    return 'compact';
  }
  if (isJWEJSONSerialization(data)) {
    return 'json';
  }
  if (isJWEFlattenedJSONSerialization(data)) {
    return 'json_flat';
  }
  throw new TypeError(`${data} は Serialized JWE ではない`);
}

export const JWECompactSerializer = {
  serialize: serializeCompact,
  deserialize: deserializeCompact,
};

export const JWEJSONSerializer = {
  serialize: serializeJSON,
  deserialize: deserializeJSON,
  is: isJWEJSONSerialization,
  equals: equalsJWEJSONSerialization,
};

export const JWEFlattenedJSONSerializer = {
  serialize: serializeFlattenedJSON,
  deserialize: deserializeFlattenedJSON,
  is: isJWEFlattenedJSONSerialization,
  equals: equalsJWEFlattenedJSONSerialization,
};

function serializeCompact(
  p_b64u: string,
  ek: JWEEncryptedKey,
  iv: JWEIV,
  c: JWECiphertext,
  tag: JWETag
): JWECompactSerialization {
  return `${p_b64u}.${BASE64URL(ek)}.${BASE64URL(iv)}.${BASE64URL(c)}.${BASE64URL(tag)}`;
}

function deserializeCompact(compact: JWECompactSerialization): {
  p_b64u: string;
  ek: JWEEncryptedKey;
  iv: JWEIV;
  c: JWECiphertext;
  tag: JWETag;
} {
  const l = compact.split('.');
  if (l.length !== 5) {
    throw new EvalError('JWS Compact Serialization の形式ではない');
  }
  const [h, ek, iv, c, tag] = l;
  return {
    p_b64u: h,
    ek: BASE64URL_DECODE(ek) as JWEEncryptedKey,
    iv: BASE64URL_DECODE(iv) as JWEIV,
    c: BASE64URL_DECODE(c) as JWECiphertext,
    tag: BASE64URL_DECODE(tag) as JWETag,
  };
}

function isJWEJSONSerialization(arg: unknown): arg is JWEJSONSerialization {
  return (
    isObject<JWEJSONSerialization>(arg) &&
    (arg.protected == null || typeof arg.protected === 'string') &&
    (arg.unprotected == null || isJOSEHeader(arg.unprotected, 'JWE')) &&
    (arg.iv == null || typeof arg.iv === 'string') &&
    (arg.aad == null || typeof arg.aad === 'string') &&
    typeof arg.ciphertext === 'string' &&
    (arg.tag == null || typeof arg.tag === 'string') &&
    Array.isArray(arg.recipients) &&
    arg.recipients.every(
      (u) =>
        isObject<{
          header?: JWEPerRecipientUnprotectedHeader;
          encrypted_key?: string;
        }>(u) &&
        (u.header == null || isJOSEHeader(u.header, 'JWE')) &&
        (u.encrypted_key == null || typeof u.encrypted_key === 'string')
    )
  );
}

function equalsJWEJSONSerialization(l?: JWEJSONSerialization, r?: JWEJSONSerialization): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of ['protected', 'iv', 'aad', 'ciphertext', 'tag'] as const) {
    if (l[n] == null && r[n] == null) continue;
    if (l[n] == null || r[n] == null) return false;
    if (l[n] === r[n]) continue;
  }
  if (!equalsJOSEHeader(l.unprotected, r.unprotected)) return false;
  return (
    l.recipients.every((ll) =>
      r.recipients.some((rr) => equalsRecipientInJWEJSONSerialization(rr, ll))
    ) &&
    r.recipients.every((rr) =>
      l.recipients.some((ll) => equalsRecipientInJWEJSONSerialization(ll, rr))
    )
  );
}

function equalsRecipientInJWEJSONSerialization(
  l?: {
    header?: JWEPerRecipientUnprotectedHeader;
    encrypted_key?: string;
  },
  r?: {
    header?: JWEPerRecipientUnprotectedHeader;
    encrypted_key?: string;
  }
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  if (l.encrypted_key !== r.encrypted_key) return false;
  if (!equalsJOSEHeader(l.header, r.header)) return false;
  return true;
}

function serializeJSON(
  c: JWECiphertext,
  rcpt:
    | { h?: JWEPerRecipientUnprotectedHeader; ek?: JWEEncryptedKey }
    | { h?: JWEPerRecipientUnprotectedHeader; ek?: JWEEncryptedKey }[],
  p_b64u?: string,
  hsu?: JWESharedUnprotectedHeader,
  iv?: JWEIV,
  aad?: JWEAAD,
  tag?: JWETag
): JWEJSONSerialization {
  return {
    protected: p_b64u,
    unprotected: hsu,
    iv: iv ? BASE64URL(iv) : undefined,
    aad: aad ? BASE64URL(aad) : undefined,
    ciphertext: BASE64URL(c),
    tag: tag ? BASE64URL(tag) : undefined,
    recipients: Array.isArray(rcpt)
      ? rcpt.map((r) => ({
          header: r.h,
          encrypted_key: r.ek ? BASE64URL(r.ek) : undefined,
        }))
      : [{ header: rcpt.h, encrypted_key: rcpt.ek ? BASE64URL(rcpt.ek) : undefined }],
  };
}

function deserializeJSON(json: JWEJSONSerialization): {
  c: JWECiphertext;
  rcpt:
    | { h?: JWEPerRecipientUnprotectedHeader; ek?: JWEEncryptedKey }
    | { h?: JWEPerRecipientUnprotectedHeader; ek?: JWEEncryptedKey }[];
  p_b64u?: string;
  hsu?: JWESharedUnprotectedHeader;
  iv: JWEIV;
  aad?: JWEAAD;
  tag: JWETag;
} {
  return {
    c: BASE64URL_DECODE(json.ciphertext) as JWECiphertext,
    rcpt:
      json.recipients.length === 1
        ? {
            h: json.recipients[0].header,
            ek: json.recipients[0].encrypted_key
              ? (BASE64URL_DECODE(json.recipients[0].encrypted_key) as JWEEncryptedKey)
              : undefined,
          }
        : json.recipients.map((r) => ({
            h: r.header,
            ek: r.encrypted_key
              ? (BASE64URL_DECODE(r.encrypted_key) as JWEEncryptedKey)
              : undefined,
          })),
    p_b64u: json.protected,
    hsu: json.unprotected,
    iv: json.iv ? (BASE64URL_DECODE(json.iv) as JWEIV) : (new Uint8Array() as JWEIV),
    aad: json.aad ? (BASE64URL_DECODE(json.aad) as JWEAAD) : undefined,
    tag: json.tag ? (BASE64URL_DECODE(json.tag) as JWETag) : (new Uint8Array() as JWETag),
  };
}

function isJWEFlattenedJSONSerialization(arg: unknown): arg is JWEFlattenedJSONSerialization {
  return (
    isObject<JWEFlattenedJSONSerialization>(arg) &&
    (arg.protected == null || typeof arg.protected === 'string') &&
    (arg.unprotected == null || isJOSEHeader(arg.unprotected, 'JWE')) &&
    (arg.iv == null || typeof arg.iv === 'string') &&
    (arg.aad == null || typeof arg.aad === 'string') &&
    typeof arg.ciphertext === 'string' &&
    (arg.tag == null || typeof arg.tag === 'string') &&
    (arg.header == null || isJOSEHeader(arg.header, 'JWE')) &&
    (arg.encrypted_key == null || typeof arg.encrypted_key === 'string')
  );
}

function equalsJWEFlattenedJSONSerialization(
  l?: JWEFlattenedJSONSerialization,
  r?: JWEFlattenedJSONSerialization
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of ['protected', 'iv', 'aad', 'ciphertext', 'tag'] as const) {
    if (l[n] == null && r[n] == null) continue;
    if (l[n] == null || r[n] == null) return false;
    if (l[n] === r[n]) continue;
  }
  if (!equalsJOSEHeader(l.unprotected, r.unprotected)) return false;
  return equalsRecipientInJWEJSONSerialization(l, r);
}

function serializeFlattenedJSON(
  c: JWECiphertext,
  h?: JWEPerRecipientUnprotectedHeader,
  ek?: JWEEncryptedKey,
  p_b64u?: string,
  hsu?: JWESharedUnprotectedHeader,
  iv?: JWEIV,
  aad?: JWEAAD,
  tag?: JWETag
): JWEFlattenedJSONSerialization {
  const json = serializeJSON(c, { h, ek }, p_b64u, hsu, iv, aad, tag);
  return {
    protected: json.protected,
    unprotected: json.unprotected,
    header: json.recipients[0].header,
    encrypted_key: json.recipients[0].encrypted_key,
    iv: json.iv,
    aad: json.aad,
    ciphertext: json.ciphertext,
    tag: json.tag,
  };
}

function deserializeFlattenedJSON(flat: JWEFlattenedJSONSerialization): {
  c: JWECiphertext;
  h?: JWEPerRecipientUnprotectedHeader;
  ek?: JWEEncryptedKey;
  p_b64u?: string;
  hsu?: JWESharedUnprotectedHeader;
  iv: JWEIV;
  aad?: JWEAAD;
  tag: JWETag;
} {
  const jwe = deserializeJSON({
    ...flat,
    recipients: [{ header: flat.header, encrypted_key: flat.encrypted_key }],
  });
  return {
    ...jwe,
    h: Array.isArray(jwe.rcpt) ? jwe.rcpt[0].h : jwe.rcpt.h,
    ek: Array.isArray(jwe.rcpt) ? jwe.rcpt[0].ek : jwe.rcpt.ek,
  };
}
