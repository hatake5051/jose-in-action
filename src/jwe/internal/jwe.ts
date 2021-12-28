import { Alg, EncAlg, ktyFromAlg } from 'iana/alg';
import { JOSEHeaderParamName, JOSEHeaderParams } from 'iana/header';
import {
  JWEAAD,
  JWECEK,
  JWECiphertext,
  JWEEncryptedKey,
  JWEIV,
  JWEPerRecipientUnprotectedHeader,
  JWEProtectedHeader,
  JWESharedUnprotectedHeader,
  JWETag,
} from 'jwe/type';
import { equalsJWK, exportPubJWK, identifyJWK, isJWK, JWK, JWKSet } from 'jwk';
import { Arrayable, ASCII, BASE64URL } from 'utility';
import {
  generateCEK,
  keyMgmtModeFromAlg,
  newDirectEncrytor,
  newDirectKeyAgreementer,
  newEncOperator,
  newKeyAgreementerWithKeyWrapping,
  newKeyEncryptor,
  newKeyWrappaer,
} from './di';
import { JWEHeader, JWEHeaderBuilder, JWEHeaderBuilderFromSerializedJWE } from './header';
import {
  JWECompactSerializer,
  JWEFlattenedJSONSerializer,
  JWEJSONSerializer,
  JWESerialization,
  jweSerializationFormat,
  JWESerializationFormat,
} from './serialize';

export class JWE {
  private constructor(
    private header: JWEHeader,
    private iv: JWEIV,
    private c: JWECiphertext,
    private tag: JWETag,
    private encryptedKey?: Arrayable<JWEEncryptedKey | undefined>,
    private aad?: JWEAAD
  ) {}

  /**
   * RFC7516#5.1 Message Encryption を行う。
   * @param alg 選択した受信者の JOSEHeader.alg. 複数人いる場合は配列で与える
   * @param keys CEK の値を決めるために Key Management Mode で使用する鍵セット
   * @param plaintext 平文
   * @param enc JOSEHeader.enc の値
   * @param options JWE を再現したり、 JOSEHeader を定めたり詳細な設定を行う場合のオプション
   * @returns
   */
  static async enc(
    alg: Arrayable<Alg<'JWE'>>,
    keys: JWKSet,
    encalg: EncAlg,
    plaintext: Uint8Array,
    options?: {
      header?: {
        p?: {
          initialValue?: JWEProtectedHeader;
          paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
          b64u?: string;
        };
        su?: {
          initialValue?: JWESharedUnprotectedHeader;
          paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
        };
        ru?: Arrayable<{
          initialValue?: JWEPerRecipientUnprotectedHeader;
          paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
        }>;
      };
      keyMgmt?: {
        cek?: JWECEK;
        eprivk?: Arrayable<JWK<'EC', 'Priv'>>;
      };
      iv?: JWEIV;
      aad?: JWEAAD;
    }
  ): Promise<JWE> {
    let algPerRcpt: Alg<'JWE'> | [Alg<'JWE'>, Alg<'JWE'>, ...Alg<'JWE'>[]];
    if (Array.isArray(alg)) {
      if (alg.length < 2) {
        throw new TypeError('alg を配列として渡す場合は長さが2以上にしてください');
      }
      algPerRcpt = [alg[0], alg[1], ...alg.slice(2)];
    } else {
      algPerRcpt = alg;
    }
    const header = JWEHeaderBuilder(algPerRcpt, encalg, options?.header);

    // Key Management を行う(Encrypted Key の生成と CEK の用意)
    let keyMgmt: { cek: JWECEK; ek?: Arrayable<JWEEncryptedKey | undefined> };
    let keyMgmtOpt = options?.keyMgmt;
    if (!keyMgmtOpt?.cek) {
      const cek = generateCEK(encalg);
      keyMgmtOpt = { ...keyMgmtOpt, cek };
    }
    if (Array.isArray(algPerRcpt)) {
      const list = await Promise.all(
        algPerRcpt.map(async (_a, i) => await sendCEK(keys, header.JOSE(i), keyMgmtOpt))
      );
      // recipient ごとに行った Key Management の整合性チェック
      if (new Set(list.map((e) => e.cek)).size != 1) {
        throw new EvalError(`複数人に対する暗号化で異なる CEK を使おうとしている`);
      }
      const cek = list[0].cek;
      list.forEach((e, i) => {
        if (e.h) header.update(e.h, i);
      });
      keyMgmt = { cek, ek: list.map((e) => e.ek) };
    } else {
      const { cek, ek, h } = await sendCEK(keys, header.JOSE(), keyMgmtOpt);
      if (h) header.update(h);
      keyMgmt = { cek, ek };
    }
    // Key Management で得られた CEK を使って
    // 平文を暗号化する。
    const { c, tag, iv } = await enc(
      encalg,
      keyMgmt.cek,
      plaintext,
      options?.iv,
      header.Protected_b64u(),
      options?.aad
    );
    return new JWE(header, iv, c, tag, keyMgmt.ek, options?.aad);
  }

  async dec(keys: JWKSet): Promise<Uint8Array> {
    let cek: JWECEK | undefined;
    if (Array.isArray(this.encryptedKey)) {
      for (let i = 0; i < this.encryptedKey.length; i++) {
        try {
          cek = await recvCEK(keys, this.header.JOSE(i), this.encryptedKey[i]);
          break;
        } catch {
          continue;
        }
      }
      if (!cek) {
        throw new EvalError(`暗号化に使われた鍵(CEK)を決定できなかった`);
      }
    } else {
      try {
        cek = await recvCEK(keys, this.header.JOSE(), this.encryptedKey);
      } catch {
        throw new EvalError(`暗号化に使われた鍵(CEK)を決定できなかった`);
      }
    }
    const encalg = this.header.JOSE().enc;
    if (!encalg) {
      throw new EvalError('コンテンツ暗号アルゴリズムの識別子がない');
    }
    const p = await dec(
      encalg,
      cek,
      this.c,
      this.tag,
      this.iv,
      this.header.Protected_b64u(),
      this.aad
    );
    return p;
  }

  serialize<S extends JWESerializationFormat>(s: S): JWESerialization<S> {
    switch (s) {
      case 'compact': {
        if (this.encryptedKey && Array.isArray(this.encryptedKey)) {
          throw new TypeError('JWE Compact Serialization は複数暗号化を表現できない');
        }

        if (this.header.PerRecipient()) {
          throw new TypeError(
            'JWE Compact Serialization は JWE PerRecipient Unprotected Header を表現できない'
          );
        }
        if (this.header.SharedUnprotected()) {
          throw new TypeError(
            'JWE Compact Serialization は JWE Shared Unprotected Header を表現できない'
          );
        }
        if (this.aad) {
          throw new TypeError('JWE Compact Serialization は JWE AAD を表現できない');
        }
        const p_b64u = this.header.Protected_b64u();
        if (!p_b64u) {
          throw new TypeError('JWE Compact Serialization では JWE Protected Header が必須');
        }
        return JWECompactSerializer.serialize(
          p_b64u,
          this.encryptedKey ?? (new Uint8Array() as JWEEncryptedKey),
          this.iv,
          this.c,
          this.tag
        ) as JWESerialization<S>;
      }
      case 'json': {
        return JWEJSONSerializer.serialize(
          this.c,
          Array.isArray(this.encryptedKey)
            ? this.encryptedKey.map((ek, i) => ({ h: this.header.PerRecipient(i), ek }))
            : { h: this.header.PerRecipient(), ek: this.encryptedKey },
          this.header.Protected_b64u(),
          this.header.SharedUnprotected(),
          this.iv,
          this.aad,
          this.tag
        ) as JWESerialization<S>;
      }
      case 'json_flat': {
        if (Array.isArray(this.encryptedKey)) {
          throw new TypeError('JWE Flattened JSON Serialization は複数暗号化を表現できない');
        }
        return JWEFlattenedJSONSerializer.serialize(
          this.c,
          this.header.PerRecipient(),
          this.encryptedKey,
          this.header.Protected_b64u(),
          this.header.SharedUnprotected(),
          this.iv,
          this.aad,
          this.tag
        ) as JWESerialization<S>;
      }
      default:
        throw new TypeError(`${s} は JWESerialization format ではない`);
    }
  }

  static deserialize(data: JWESerialization): JWE {
    switch (jweSerializationFormat(data)) {
      case 'compact': {
        const { p_b64u, c, tag, iv, ek } = JWECompactSerializer.deserialize(
          data as JWESerialization<'compact'>
        );

        const header = JWEHeaderBuilderFromSerializedJWE(p_b64u);
        return new JWE(header, iv, c, tag, ek);
      }
      case 'json': {
        const { c, rcpt, p_b64u, hsu, iv, aad, tag } = JWEJSONSerializer.deserialize(
          data as JWESerialization<'json'>
        );
        const header = JWEHeaderBuilderFromSerializedJWE(
          p_b64u,
          hsu,
          Array.isArray(rcpt) ? rcpt.map((r) => r.h) : rcpt.h
        );
        return new JWE(
          header,
          iv,
          c,
          tag,
          Array.isArray(rcpt) ? rcpt.map((r) => r.ek) : rcpt.ek,
          aad
        );
      }
      case 'json_flat': {
        const { c, h, ek, p_b64u, hsu, iv, aad, tag } = JWEFlattenedJSONSerializer.deserialize(
          data as JWESerialization<'json_flat'>
        );
        const header = JWEHeaderBuilderFromSerializedJWE(p_b64u, hsu, h);
        return new JWE(header, iv, c, tag, ek, aad);
      }
    }
  }
}

async function enc(
  encalg: EncAlg,
  cek: JWECEK,
  m: Uint8Array,
  iv?: JWEIV,
  p_b64u?: string,
  aad?: JWEAAD
): Promise<{ c: JWECiphertext; tag: JWETag; iv: JWEIV }> {
  let aad_str = p_b64u ?? '';
  if (aad) {
    aad_str += '.' + BASE64URL(aad);
  }
  return await newEncOperator(encalg).enc(encalg, cek, m, ASCII(aad_str) as JWEAAD, iv);
}

async function dec(
  encalg: EncAlg,
  cek: JWECEK,
  c: JWECiphertext,
  tag: JWETag,
  iv: JWEIV,
  p_b64u?: string,
  aad?: JWEAAD
): Promise<Uint8Array> {
  let aad_str = p_b64u ?? '';
  if (aad) {
    aad_str += '.' + BASE64URL(aad);
  }
  return await newEncOperator(encalg).dec(encalg, cek, iv, ASCII(aad_str) as JWEAAD, c, tag);
}

async function sendCEK(
  keys: JWKSet,
  h: JOSEHeaderParams<'JWE'>,
  options?: { cek?: JWECEK; eprivk?: Arrayable<JWK<'EC', 'Priv'>> }
): Promise<{ cek: JWECEK; ek?: JWEEncryptedKey; h?: JOSEHeaderParams<'JWE'> }> {
  if (!h.alg) {
    throw new TypeError('alg が選択されていない');
  }
  const key = identifyJWK(keys, { ...h, kty: ktyFromAlg(h.alg) });
  switch (keyMgmtModeFromAlg(h.alg)) {
    case 'KE': {
      if (!options?.cek) throw new EvalError(`Key Encryption では CEK を与えてください`);
      if (!isJWK(key, 'Pub'))
        throw new TypeError(`JWE 生成時の Key Encryption では秘密鍵を使いません`);
      const ek = await newKeyEncryptor(h.alg).enc(h.alg, key, options.cek);
      return { ek, cek: options.cek };
    }
    case 'KW': {
      if (!options?.cek) throw new EvalError(`Key Wrapping では CEK を与えてください`);
      const { ek, h: updatedH } = await newKeyWrappaer(h.alg).wrap(key, options.cek, h);
      return { ek, cek: options.cek, h: updatedH };
    }
    case 'DKA': {
      const eprivk = !options?.eprivk
        ? undefined
        : Array.isArray(options.eprivk)
        ? options.eprivk.find((k) => equalsJWK(exportPubJWK(k), h.epk))
        : options.eprivk;
      if (!isJWK(key, 'Pub'))
        throw new TypeError(`JWE 生成時の Direct Key Agreement では秘密鍵を使いません`);
      const { cek, h: updatedH } = await newDirectKeyAgreementer(h.alg).partyU(key, h, eprivk);
      return { cek, h: updatedH };
    }
    case 'KAKW': {
      const eprivk = !options?.eprivk
        ? undefined
        : Array.isArray(options.eprivk)
        ? options.eprivk.find((k) => equalsJWK(exportPubJWK(k), h.epk))
        : options.eprivk;
      if (!options?.cek)
        throw new EvalError(`Key Agreement with Key Wrapping では CEK を与えてください`);
      if (!isJWK(key, 'Pub'))
        throw new TypeError(`JWE 生成時の Key Agreement with Key Wrappingn では秘密鍵を使いません`);
      const { ek, h: updatedH } = await newKeyAgreementerWithKeyWrapping(h.alg).wrap(
        key,
        options.cek,
        h,
        eprivk
      );
      return { ek, cek: options.cek, h: updatedH };
    }
    case 'DE': {
      const cek = await newDirectEncrytor(h.alg).extract(h.alg, key);
      return { cek };
    }
  }
}

async function recvCEK(
  keys: JWKSet,
  h: JOSEHeaderParams<'JWE'>,
  ek?: JWEEncryptedKey
): Promise<JWECEK> {
  if (!h.alg) {
    throw new TypeError('alg が選択されていない');
  }
  const key = identifyJWK(keys, { ...h, kty: ktyFromAlg(h.alg) });
  if (!isJWK(key, 'Priv')) {
    throw new EvalError('Encrypted Key から CEK を決定する秘密鍵を同定できなかった');
  }
  switch (keyMgmtModeFromAlg(h.alg)) {
    case 'KE': {
      if (!ek) throw new EvalError(`Encrypted Key を与えてください`);
      const cek = await newKeyEncryptor(h.alg).dec(h.alg, key, ek);
      return cek;
    }
    case 'KW': {
      if (!ek) throw new EvalError(`Encrypted Key を与えてください`);
      const cek = await newKeyWrappaer(h.alg).unwrap(key, ek, h);
      return cek;
    }
    case 'DKA': {
      const cek = await newDirectKeyAgreementer(h.alg).partyV(key, h);
      return cek;
    }
    case 'KAKW': {
      if (!ek) throw new EvalError(`Encrypted Key を与えてください`);
      const cek = await newKeyAgreementerWithKeyWrapping(h.alg).unwrap(key, ek, h);
      return cek;
    }
    case 'DE': {
      const cek = await newDirectEncrytor(h.alg).extract(h.alg, key);
      return cek;
    }
  }
}
