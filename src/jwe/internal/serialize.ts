import {
  equalsJWEPerRecipientUnprotectedHeader,
  equalsJWESharedUnprotectedHeader,
  isJWEPerRecipientUnprotectedHeader,
  isJWESharedUnprotectedHeader,
} from 'jwe';
import { JWEAAD, JWECiphertext, JWEEncryptedKey, JWEIV, JWETag } from 'jwe/type';
import { BASE64URL, BASE64URL_DECODE, isObject, UTF8, UTF8_DECODE } from 'utility';
import {
  JWEPerRecipientUnprotectedHeader,
  JWEProtectedHeader,
  JWESharedUnprotectedHeader,
} from './header';

export {
  JWESerialization,
  SerializationType,
  serializationType,
  JWECompactSerialization,
  serializeCompact,
  deserializeCompact,
  JWEJSONSerialization,
  isJWEJSONSerialization,
  equalsJWEJSONSerialization,
  serializeJSON,
  deserializeJSON,
  JWEFlattenedJSONSerialization,
  isJWEFlattenedJSONSerialization,
  equalsJWEFlattenedJSONSerialization,
  serializeFlattenedJSON,
  deserializeFlattenedJSON,
};

type JWESerialization = 'compact' | 'json' | 'json-flat';

type SerializationType<S extends JWESerialization = JWESerialization> = S extends 'compact'
  ? JWECompactSerialization
  : S extends 'json'
  ? JWEJSONSerialization
  : S extends 'json-flat'
  ? JWEFlattenedJSONSerialization
  : never;

function serializationType(data: unknown): JWESerialization {
  if (typeof data == 'string') {
    return 'compact';
  }
  if (typeof data == 'object' && data != null) {
    if ('recipients' in data) return 'json';
    return 'json-flat';
  }
  throw new TypeError(`${data} は JWSSerialization ではない`);
}

type JWECompactSerialization = string;

function serializeCompact(
  h: JWEProtectedHeader,
  ek: JWEEncryptedKey,
  iv: JWEIV,
  c: JWECiphertext,
  tag: JWETag
): JWECompactSerialization {
  // let ans = BASE64URL(UTF8(JSON.stringify(h))) + '.';
  // if (ek) {
  //   ans += BASE64URL(ek);
  // }
  // ans += '.';
  // if (iv) {
  //   ans += BASE64URL(iv);
  // }
  // ans += '.' + BASE64URL(c) + '.';
  // if (tag) {
  //   ans += BASE64URL(tag);
  // }
  // return ans;
  const h_b64u = BASE64URL(UTF8(JSON.stringify(h)));
  return `${h_b64u}.${BASE64URL(ek)}.${BASE64URL(iv)}.${BASE64URL(c)}.${BASE64URL(tag)}`;
}

function deserializeCompact(compact: JWECompactSerialization): {
  h: JWEProtectedHeader;
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
    h: JSON.parse(UTF8_DECODE(BASE64URL_DECODE(h))),
    ek: BASE64URL_DECODE(ek),
    iv: BASE64URL_DECODE(iv),
    c: BASE64URL_DECODE(c),
    tag: BASE64URL_DECODE(tag),
  };
}

type JWEJSONSerialization = {
  protected?: string;
  unprotected?: JWESharedUnprotectedHeader;
  iv?: string;
  aad?: string;
  ciphertext: string;
  tag?: string;
  recipients: {
    header?: JWEPerRecipientUnprotectedHeader;
    encrypted_key?: string;
  }[];
};

const isJWEJSONSerialization = (arg: unknown): arg is JWEJSONSerialization =>
  isObject<JWEJSONSerialization>(arg) &&
  (arg.protected == null || typeof arg.protected === 'string') &&
  (arg.unprotected == null || isJWESharedUnprotectedHeader(arg.unprotected)) &&
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
      (u.header == null || isJWEPerRecipientUnprotectedHeader(u.header)) &&
      (u.encrypted_key == null || typeof u.encrypted_key === 'string')
  );

function equalsJWEJSONSerialization(l?: JWEJSONSerialization, r?: JWEJSONSerialization): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of ['protected', 'iv', 'aad', 'ciphertext', 'tag'] as const) {
    if (l[n] == null && r[n] == null) continue;
    if (l[n] == null || r[n] == null) return false;
    if (l[n] === r[n]) continue;
  }
  if (!equalsJWESharedUnprotectedHeader(l.unprotected, r.unprotected)) return false;
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
  if (!equalsJWEPerRecipientUnprotectedHeader(l.header, r.header)) return false;
  return true;
}

function serializeJSON(
  c: JWECiphertext,
  rcpt:
    | { h?: JWEPerRecipientUnprotectedHeader; ek?: JWEEncryptedKey }
    | { h?: JWEPerRecipientUnprotectedHeader; ek?: JWEEncryptedKey }[],
  hp?: JWEProtectedHeader,
  hsu?: JWESharedUnprotectedHeader,
  iv?: JWEIV,
  aad?: JWEAAD,
  tag?: JWETag
): JWEJSONSerialization {
  return {
    protected: hp ? BASE64URL(UTF8(JSON.stringify(hp))) : undefined,
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
  hp?: JWEProtectedHeader;
  hsu?: JWESharedUnprotectedHeader;
  iv: JWEIV;
  aad?: JWEAAD;
  tag: JWETag;
} {
  return {
    c: BASE64URL_DECODE(json.ciphertext),
    rcpt:
      json.recipients.length === 1
        ? {
            h: json.recipients[0].header,
            ek: json.recipients[0].encrypted_key
              ? BASE64URL_DECODE(json.recipients[0].encrypted_key)
              : undefined,
          }
        : json.recipients.map((r) => ({
            h: r.header,
            ek: r.encrypted_key ? BASE64URL_DECODE(r.encrypted_key) : undefined,
          })),
    hp: json.protected ? JSON.parse(UTF8_DECODE(BASE64URL_DECODE(json.protected))) : undefined,
    hsu: json.unprotected,
    iv: json.iv ? BASE64URL_DECODE(json.iv) : new Uint8Array(),
    aad: json.aad ? BASE64URL_DECODE(json.aad) : undefined,
    tag: json.tag ? BASE64URL_DECODE(json.tag) : new Uint8Array(),
  };
}

type JWEFlattenedJSONSerialization = {
  protected?: string;
  unprotected?: JWESharedUnprotectedHeader;
  header?: JWEPerRecipientUnprotectedHeader;
  encrypted_key?: string;
  iv?: string;
  aad?: string;
  ciphertext: string;
  tag?: string;
};

const isJWEFlattenedJSONSerialization = (arg: unknown): arg is JWEFlattenedJSONSerialization =>
  isObject<JWEFlattenedJSONSerialization>(arg) &&
  (arg.protected == null || typeof arg.protected === 'string') &&
  (arg.unprotected == null || isJWESharedUnprotectedHeader(arg.unprotected)) &&
  (arg.iv == null || typeof arg.iv === 'string') &&
  (arg.aad == null || typeof arg.aad === 'string') &&
  typeof arg.ciphertext === 'string' &&
  (arg.tag == null || typeof arg.tag === 'string') &&
  (arg.header == null || isJWEPerRecipientUnprotectedHeader(arg.header)) &&
  (arg.encrypted_key == null || typeof arg.encrypted_key === 'string');

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
  if (!equalsJWESharedUnprotectedHeader(l.unprotected, r.unprotected)) return false;
  return equalsRecipientInJWEJSONSerialization(l, r);
}

function serializeFlattenedJSON(
  c: JWECiphertext,
  h?: JWEPerRecipientUnprotectedHeader,
  ek?: JWEEncryptedKey,
  hp?: JWEProtectedHeader,
  hsu?: JWESharedUnprotectedHeader,
  iv?: JWEIV,
  aad?: JWEAAD,
  tag?: JWETag
): JWEFlattenedJSONSerialization {
  const json = serializeJSON(c, { h, ek }, hp, hsu, iv, aad, tag);
  return {
    ...json,
    header: json.recipients[0].header,
    encrypted_key: json.recipients[0].encrypted_key,
  };
}

function deserializeFlattenedJSON(flat: JWEFlattenedJSONSerialization): {
  c: JWECiphertext;
  h?: JWEPerRecipientUnprotectedHeader;
  ek?: JWEEncryptedKey;
  hp?: JWEProtectedHeader;
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
