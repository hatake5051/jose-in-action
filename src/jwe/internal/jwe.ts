import { Kty, ktyFromAlg } from 'iana';
import { JWEAAD, JWECEK, JWECiphertext, JWEEncryptedKey, JWEIV, JWETag } from 'jwe/type';
import { equalsJWK, exportPublicKey, identifyJWK, isJWK, JWK, JWKSet } from 'jwk';
import { ASCII, BASE64URL, UTF8 } from 'utility';
import {
  JWEEnc,
  newDirectEncrytor,
  newDirectKeyAgreementer,
  newEncOperator,
  newKeyAgreementerWithKeyWrapping,
  newKeyEncryptor,
  newKeyWrappaer,
} from './di';
import {
  JWEHeader,
  JWEPerRecipientUnprotectedHeader,
  JWEProtectedHeader,
  JWESharedUnprotectedHeader,
} from './header';
import {
  deserializeCompact,
  deserializeFlattenedJSON,
  deserializeJSON,
  JWESerialization,
  serializationType,
  SerializationType,
  serializeCompact,
  serializeFlattenedJSON,
  serializeJSON,
} from './serialize';

export class JWE {
  private constructor(
    private rcpt:
      | { h?: JWEPerRecipientUnprotectedHeader; ek?: JWEEncryptedKey }
      | { h?: JWEPerRecipientUnprotectedHeader; ek?: JWEEncryptedKey }[],
    private iv: JWEIV,
    private c: JWECiphertext,
    private tag: JWETag,
    private p?: JWEProtectedHeader,
    private su?: JWESharedUnprotectedHeader,
    private aad?: JWEAAD
  ) {}

  /**
   * RFC7516#5.1 Message Encryption を行う。
   * @param keys
   * @param plaintext
   * @param h
   * @param iv
   * @param aad
   * @param options
   * @returns
   */
  static async enc(
    keys: JWKSet,
    plaintext: Uint8Array,
    h: {
      p?: JWEProtectedHeader;
      su?: JWESharedUnprotectedHeader;
      ru?: JWEPerRecipientUnprotectedHeader | JWEPerRecipientUnprotectedHeader[];
    },
    iv: JWEIV,
    aad?: JWEAAD,
    options?: {
      cek?: JWECEK;
      eprivk?: JWK<'EC', 'Priv'> | JWK<'EC', 'Priv'>[];
    }
  ): Promise<JWE> {
    // recipient ごとに JOSEHeader を用意する
    const hlist = !h.ru
      ? [new JWEHeader(h.p, h.su)]
      : !Array.isArray(h.ru)
      ? [new JWEHeader(h.p, h.su, h.ru)]
      : h.ru.length === 0
      ? [new JWEHeader(h.p, h.su)]
      : h.ru.map((rh) => new JWEHeader(h.p, h.su, rh));
    // recipient ごとに Key Management を行う(Encrypted Key の生成と CEK の用意)
    const list = await Promise.all(
      hlist.map(async (header) => {
        const { ek, cek } = await sendCEK(keys, header, options);
        return { ek, cek, rh: header.PerRecipientUnprotected };
      })
    );
    // Key Management で得られた CEK を使って
    if (new Set(list.map((e) => e.cek)).size != 1)
      throw new EvalError(`複数人に対する暗号化で異なる CEK を使おうとしている`);
    const cek: JWECEK = list[0].cek;
    // 平文を暗号化する。
    const { c, tag } = await enc(cek, hlist[0], plaintext, iv, aad);
    const rcpt = list.map((e) => ({ ek: e.ek, h: e.rh }));
    if (rcpt.length === 1) {
      return new JWE(rcpt[0], iv, c, tag, h.p, h.su, aad);
    }
    return new JWE(rcpt, iv, c, tag, h.p, h.su, aad);
  }

  async dec(keys: JWKSet): Promise<Uint8Array> {
    const hlist = !this.rcpt
      ? [{ h: new JWEHeader(this.p, this.su), ek: undefined }]
      : !Array.isArray(this.rcpt)
      ? [{ h: new JWEHeader(this.p, this.su, this.rcpt.h), ek: this.rcpt.ek }]
      : this.rcpt.length === 0
      ? [{ h: new JWEHeader(this.p, this.su), ek: undefined }]
      : this.rcpt.map((r) => ({ h: new JWEHeader(this.p, this.su, r.h), ek: r.ek }));
    let key: unknown;
    const filtered = hlist.filter((h) => {
      try {
        key = identifyJWK(h.h.JOSEHeader, keys);
        return true;
      } catch {
        return false;
      }
    });
    if (filtered.length !== 1) throw new EvalError(`暗号化に使われた鍵を同定できなかった`);
    if (!(isJWK(key, 'RSA', 'Priv') || isJWK(key, 'EC', 'Priv') || isJWK(key, 'oct')))
      throw new EvalError(`暗号化に使われた鍵に対応する秘密鍵を所持していない`);
    const cek = await recvCEK(key, filtered[0].h, filtered[0].ek);
    const p = await dec(cek, filtered[0].h, this.c, this.tag, this.iv, this.aad);
    return p;
  }

  serialize<S extends JWESerialization>(s: S): SerializationType<S> {
    switch (s) {
      case 'compact':
        if (Array.isArray(this.rcpt)) {
          throw new TypeError('JWE Compact Serialization は複数暗号化を表現できない');
        }
        if (this.rcpt.h) {
          throw new TypeError(
            'JWE Compact Serialization は JWE PerRecipient Unprotected Header を表現できない'
          );
        }
        if (this.su) {
          throw new TypeError(
            'JWE Compact Serialization は JWE Shared Unprotected Header を表現できない'
          );
        }
        if (this.aad) {
          throw new TypeError('JWE Compact Serialization は JWE AAD を表現できない');
        }
        if (!this.p) {
          throw new TypeError('JWE Compact Serialization では JWE Protected Header が必須');
        }
        return serializeCompact(
          this.p,
          this.rcpt.ek ?? new Uint8Array(),
          this.iv,
          this.c,
          this.tag
        ) as SerializationType<S>;
      case 'json':
        return serializeJSON(
          this.c,
          this.rcpt,
          this.p,
          this.su,
          this.iv,
          this.aad,
          this.tag
        ) as SerializationType<S>;
      case 'json-flat':
        if (Array.isArray(this.rcpt)) {
          throw new TypeError('JWE Flattened JSON Serialization は複数暗号化を表現できない');
        }
        return serializeFlattenedJSON(
          this.c,
          this.rcpt.h,
          this.rcpt.ek,
          this.p,
          this.su,
          this.iv,
          this.aad,
          this.tag
        ) as SerializationType<S>;
      default:
        throw new TypeError(`${s} は JWESerialization format ではない`);
    }
  }

  static deserialize(data: SerializationType): JWE {
    switch (serializationType(data)) {
      case 'compact': {
        const { h, c, tag, iv, ek } = deserializeCompact(data as SerializationType<'compact'>);
        return new JWE({ ek }, iv, c, tag, h);
      }
      case 'json': {
        const { c, rcpt, hp, hsu, iv, aad, tag } = deserializeJSON(
          data as SerializationType<'json'>
        );
        return new JWE(rcpt, iv, c, tag, hp, hsu, aad);
      }
      case 'json-flat': {
        const { c, h, ek, hp, hsu, iv, aad, tag } = deserializeFlattenedJSON(
          data as SerializationType<'json-flat'>
        );
        return new JWE({ h, ek }, iv, c, tag, hp, hsu, aad);
      }
    }
  }
}

async function enc(
  cek: JWECEK,
  h: { Protected?: JWEProtectedHeader; Enc: JWEEnc },
  m: Uint8Array,
  iv: JWEIV,
  aad?: JWEAAD
): Promise<{ c: JWECiphertext; tag: JWETag }> {
  let aad_str = '';
  if (h.Protected) {
    aad_str += BASE64URL(UTF8(JSON.stringify(h.Protected)));
  }
  if (aad) {
    aad_str += '.' + BASE64URL(aad);
  }
  return await newEncOperator(h.Enc).enc(h.Enc, cek, iv, ASCII(aad_str), m);
}

async function dec(
  cek: JWECEK,
  h: JWEHeader,
  c: JWECiphertext,
  tag: JWETag,
  iv: JWEIV,
  aad?: JWEAAD
): Promise<Uint8Array> {
  let aad_str = '';
  if (h.Protected) {
    aad_str += BASE64URL(UTF8(JSON.stringify(h.Protected)));
  }
  if (aad) {
    aad_str += '.' + BASE64URL(aad);
  }
  return await newEncOperator(h.Enc).dec(h.Enc, cek, iv, ASCII(aad_str), c, tag);
}

async function sendCEK(
  keys: JWKSet,
  h: JWEHeader,
  options?: { cek?: JWECEK; eprivk?: JWK<'EC', 'Priv'> | JWK<'EC', 'Priv'>[] }
): Promise<{ cek: JWECEK; ek?: JWEEncryptedKey }> {
  if (h.cast('KE')) {
    if (!options?.cek) throw new EvalError(`Key Encryption では CEK を与えてください`);
    const key = identifyJWK<typeof h.Alg>(h.JOSEHeader, keys);
    const ek = await newKeyEncryptor(h.Alg).enc(h.Alg, key, options.cek);
    return { ek, cek: options.cek };
  } else if (h.cast('KW')) {
    if (!options?.cek) throw new EvalError(`Key Wrapping では CEK を与えてください`);
    const key = identifyJWK<typeof h.Alg>(h.JOSEHeader, keys);
    const ek = await newKeyWrappaer(h.Alg).wrap(key, options.cek, h.JOSEHeader);
    return { ek, cek: options.cek };
  } else if (h.cast('DKA')) {
    if (options?.cek) throw new EvalError(`Direct Key Agreement では CEK を与えないでください`);
    if (!options?.eprivk)
      throw new EvalError(`Direct Key Agreement では Ephemeral Private Key を与えてください`);
    const eprivk = Array.isArray(options.eprivk)
      ? options.eprivk.find((k) => equalsJWK(exportPublicKey(k), h.JOSEHeader.epk))
      : options.eprivk;
    if (!eprivk)
      throw new EvalError(`Direct Key Agreement では Ephemeral Private Key を与えてください`);
    const key = identifyJWK<typeof h.Alg>(h.JOSEHeader, keys);
    const cek = await newDirectKeyAgreementer(h.Alg).partyU(key, h.JOSEHeader, eprivk);
    return { cek };
  } else if (h.cast('KAKW')) {
    if (!options?.eprivk)
      throw new EvalError(
        `Key Agreement with Key Wrapping では Ephemeral Private Key を与えてください`
      );
    const eprivk = Array.isArray(options.eprivk)
      ? options.eprivk.find((k) => equalsJWK(exportPublicKey(k), h.JOSEHeader.epk))
      : options.eprivk;
    if (!eprivk)
      throw new EvalError(`Direct Key Agreement では Ephemeral Private Key を与えてください`);
    if (!options?.cek)
      throw new EvalError(`Key Agreement with Key Wrapping では CEK を与えてください`);
    const key = identifyJWK<typeof h.Alg>(h.JOSEHeader, keys);
    const ek = await newKeyAgreementerWithKeyWrapping(h.Alg).wrap(
      key,
      options.cek,
      h.JOSEHeader,
      eprivk
    );
    return { ek, cek: options.cek };
  } else if (h.cast('DE')) {
    if (options?.cek) throw new EvalError(`Direct Encryption では CEK を与えないでください`);
    const key = identifyJWK<typeof h.Alg>(h.JOSEHeader, keys);
    const cek = await newDirectEncrytor(h.Alg).extract(h.Alg, key);
    return { cek };
  }
  throw new EvalError(`CEK を決定できませんでした`);
}

async function recvCEK(key: JWK<Kty, 'Priv'>, h: JWEHeader, ek?: JWEEncryptedKey): Promise<JWECEK> {
  if (h.cast('KE')) {
    if (key.kty !== ktyFromAlg(h.Alg)) throw new EvalError(`適切な秘密鍵ではない`);
    if (!ek) throw new EvalError(`Encrypted Key を与えてください`);
    const cek = await newKeyEncryptor(h.Alg).dec(h.Alg, key, ek);
    return cek;
  } else if (h.cast('KW')) {
    if (key.kty !== ktyFromAlg(h.Alg)) throw new EvalError(`適切な秘密鍵ではない`);
    if (!ek) throw new EvalError(`Encrypted Key を与えてください`);
    const cek = await newKeyWrappaer(h.Alg).unwrap(key, ek, h.JOSEHeader);
    return cek;
  } else if (h.cast('DKA')) {
    if (key.kty !== ktyFromAlg(h.Alg)) throw new EvalError(`適切な秘密鍵ではない`);
    const cek = await newDirectKeyAgreementer(h.Alg).partyV(key, h.JOSEHeader);
    return cek;
  } else if (h.cast('KAKW')) {
    if (key.kty !== ktyFromAlg(h.Alg)) throw new EvalError(`適切な秘密鍵ではない`);
    if (!ek) throw new EvalError(`Encrypted Key を与えてください`);
    const cek = await newKeyAgreementerWithKeyWrapping(h.Alg).unwrap(key, ek, h.JOSEHeader);
    return cek;
  } else if (h.cast('DE')) {
    if (key.kty !== ktyFromAlg(h.Alg)) throw new EvalError(`適切な秘密鍵ではない`);
    const cek = await newDirectEncrytor(h.Alg).extract(h.Alg, key);
    return cek;
  }
  throw new EvalError(`CEK を決定できませんでした`);
}
