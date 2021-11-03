import { JWECiphertext, JWEEncryptedKey, JWEIV, JWETag } from 'jwe/type';
import { BASE64URL, BASE64URL_DECODE, UTF8, UTF8_DECODE } from 'utility';
import {
  JWEPerRecipientUnprotectedHeader,
  JWEProtectedHeader,
  JWESharedUnprotectedHeader,
} from './header';

type JWESerialization = 'compact' | 'json' | 'json-flat';

type SerializationType<S extends JWESerialization> = S extends 'compact'
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
  c: JWECiphertext,
  tag: JWETag,
  iv?: JWEIV,
  ek?: JWEEncryptedKey
): JWECompactSerialization {
  let ans = BASE64URL(UTF8(JSON.stringify(h))) + '.';
  if (ek) {
    ans += BASE64URL(ek);
  }
  ans += '.';
  if (iv) {
    ans += BASE64URL(iv);
  }
  ans += '.' + BASE64URL(c) + '.' + BASE64URL(tag);
  return ans;
}

function deserializeCompact(compact: JWECompactSerialization): {
  h: JWEProtectedHeader;
  c: JWECiphertext;
  tag: JWETag;
  iv?: JWEIV;
  ek?: JWEEncryptedKey;
} {
  const l = compact.split('.');
  if (l.length !== 5) {
    throw new EvalError('JWS Compact Serialization の形式ではない');
  }
  const [h, ek, iv, c, tag] = l;
  return {
    h: JSON.parse(UTF8_DECODE(BASE64URL_DECODE(h))),
    ek: ek === '' ? undefined : BASE64URL_DECODE(ek),
    c: BASE64URL_DECODE(c),
    tag: BASE64URL_DECODE(tag),
    iv: iv === '' ? undefined : BASE64URL_DECODE(iv),
  };
}

type JWEJSONSerialization = {
  protected?: string;
  unprotected?: JWESharedUnprotectedHeader;
  iv?: string;
  aad?: string;
  ciphertext: string;
  tag?: string;
  recipients?: {
    header?: JWEPerRecipientUnprotectedHeader;
    encrypted_key?: string;
  }[];
};

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
