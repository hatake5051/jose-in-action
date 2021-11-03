import { Kty, ktyFromAlg } from 'iana';
import { JWEAAD, JWECEK, JWECiphertext, JWEEncryptedKey, JWEIV, JWETag } from 'jwe/type';
import { equalsJWK, exportPublicKey, identifyJWK, isJWK, JWK, JWKSet } from 'jwk';
import { ASCII, BASE64URL, UTF8 } from 'utility';
import {
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

class JWE {
  private constructor(
    private c: JWECiphertext,
    private tag: JWETag,
    private iv: JWEIV,
    private p?: JWEProtectedHeader,
    private su?: JWESharedUnprotectedHeader,
    private aad?: JWEAAD,
    private rcpt?:
      | { h?: JWEPerRecipientUnprotectedHeader; ek?: JWEEncryptedKey }
      | { h?: JWEPerRecipientUnprotectedHeader; ek?: JWEEncryptedKey }[]
  ) {}

  static async enc(
    keys: JWKSet,
    p: Uint8Array,
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
    const hlist = !h.ru
      ? [new JWEHeader(h.p, h.su)]
      : !Array.isArray(h.ru)
      ? [new JWEHeader(h.p, h.su, h.ru)]
      : h.ru.length === 0
      ? [new JWEHeader(h.p, h.su)]
      : h.ru.map((rh) => new JWEHeader(h.p, h.su, rh));
    const list = await Promise.all(
      hlist.map(async (header) => {
        const { ek, cek } = await sendCEK(keys, header, options);
        return { ek, cek, rh: header.PerRecipientUnprotected };
      })
    );
    if (new Set(list.map((e) => e.cek)).size != 1)
      throw new EvalError(`複数人に対する暗号化で異なる CEK を使おうとしている`);
    const cek: JWECEK = list[0].cek;
    const { c, tag } = await enc(cek, hlist[0], p, iv, aad);
    const rcpt = list.map((e) => ({ ek: e.ek, h: e.rh }));
    if (rcpt.length === 1) {
      return new JWE(c, tag, iv, h.p, h.su, aad, rcpt[0]);
    }
    return new JWE(c, tag, iv, h.p, h.su, aad, rcpt);
  }

  async dec(keys: JWKSet): Promise<Uint8Array> {
    const hlist = !this.rcpt
      ? [{ h: new JWEHeader(this.p, this.su), ek: undefined }]
      : !Array.isArray(this.rcpt)
      ? [{ h: new JWEHeader(this.p, this.su, this.rcpt.h), ek: undefined }]
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
}

async function enc(
  cek: JWECEK,
  h: JWEHeader,
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
