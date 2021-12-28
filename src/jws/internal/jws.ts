// --------------------BEGIN JWS implementation --------------------

import { Alg, ktyFromAlg } from 'iana/alg';
import { JOSEHeaderParamName } from 'iana/header';
import { identifyJWK, isJWK, JWKSet } from 'jwk';
import { JWSPayload, JWSProtectedHeader, JWSSignature, JWSUnprotectedHeader } from 'jws/type';
import { Arrayable, ASCII, BASE64URL } from 'utility';
import { JWSOpeModeFromAlg, newMacOperator, newSigOperator } from './di';
import { JWSHeader } from './header';
import {
  JWSCompactSerializer,
  JWSFlattenedJSONSerializer,
  JWSJSONSerializer,
  JWSSerialization,
  JWSSerializationFormat,
  jwsSerializationFormat,
} from './serialize';

export { JWS };

/**
 * JWS はデジタル署名もしくはメッセージ認証コードで保護されたコンテンツを表現する JSON ベースのデータ構造である。
 */
class JWS {
  private constructor(
    // 完全性が保護されるコンテンツ
    private m: JWSPayload,
    // 署名値と署名操作を表すヘッダーからなる。複数署名の場合は配列になる
    private hs: Arrayable<{ header: JWSHeader; sig: JWSSignature }>
  ) {}

  /**
   * RFC7515#5.1 Message Signature or MAC Computation
   * @param alg JWS Signature を計算するためのアルゴリズム識別子。複数署名する場合は配列として与える。
   * @param keys JWS Signature を計算するために使う署名鍵を含む JWK Set
   * @param m JWS Payload として使うコンテンツ
   * @param options JOSE Header を構成するための情報をオプションとして与えることができる。
   * `header` パラメータに引数 `alg` で与えたのと同じ順番でヘッダに関する情報を与える。
   * 各ヘッダに関する情報は Protected Header に関するものを`p` パラメータへ、 Unprotected Header に関するものを `u` パラメータで与える。
   * それぞれは、 `initialValue` に初期値を与えることができる。 `paramNames` を指定すると、各ヘッダに組み込む値を制限できる。
   * Protected Header にかぎり、 `b64u` パラメータにより Protected Header の base64url 表現を与えることもできる。
   * これら情報の無矛盾性は Header 構築時に検証される。
   * これらを指定しない場合は次の通り。
   * `alg` は Protected Header に組み込まれる。 Signature 計算時に生成したヘッダパラメータは `alg` と同じ方のヘッダへ組み込まれる。
   * @returns JWS を返す。 `JWS.serialize` によってシリアライゼーションした値を得ることができる。
   */
  static async produce(
    alg: Arrayable<Alg<'JWS'>>,
    keys: JWKSet,
    m: JWSPayload,
    options?: {
      header?: Arrayable<{
        p?: {
          initialValue?: JWSProtectedHeader;
          paramNames?: Set<JOSEHeaderParamName<'JWS'>>;
          b64u?: string;
        };
        u?: {
          initialValue?: JWSUnprotectedHeader;
          paramNames?: Set<JOSEHeaderParamName<'JWS'>>;
        };
      }>;
    }
  ): Promise<JWS> {
    let headerPerRcpt: JWSHeader | [JWSHeader, JWSHeader, ...JWSHeader[]];
    if (Array.isArray(alg)) {
      if (alg.length < 2) {
        throw new TypeError('alg を配列として渡す場合は長さが2以上にしてください');
      }
      if (!options?.header) {
        const h = alg.map((a) => JWSHeader.build(a));
        headerPerRcpt = [h[0], h[1], ...h.slice(2)];
      } else {
        const oh = options.header;
        if (!Array.isArray(oh) || oh.length !== alg.length) {
          throw new TypeError(
            'alg を配列としてわたし、オプションを指定する場合は同じ長さの配列にしてください。さらに、インデックスが同じ受信者を表すようにしてください'
          );
        }
        const h = alg.map((a, i) => JWSHeader.build(a, oh[i]));
        headerPerRcpt = [h[0], h[1], ...h.slice(2)];
      }
    } else {
      const oh = options?.header;
      if (oh && Array.isArray(oh)) {
        throw new TypeError('alg が一つの時は、オプションを複数指定しないでください');
      }
      headerPerRcpt = JWSHeader.build(alg, oh);
    }

    // ヘッダーごとにコンテンツに対して署名や MAC 計算を行う。
    // 計算の実体は sign で実装。
    if (Array.isArray(headerPerRcpt)) {
      const hsList = await Promise.all(
        headerPerRcpt.map(async (header) => ({ header, sig: await sign(keys, m, header) }))
      );
      return new JWS(m, hsList);
    }
    const sig = await sign(keys, m, headerPerRcpt);
    return new JWS(m, { header: headerPerRcpt, sig });
  }

  async validate(keys: JWKSet, isAllValidation = true): Promise<boolean> {
    const hsList = Array.isArray(this.hs) ? this.hs : [this.hs];
    const verifiedList = await Promise.all(
      hsList.map(async (hs) => await verify(keys, this.m, hs.header, hs.sig))
    );
    return verifiedList.reduce((prev, now) => (isAllValidation ? prev && now : prev || now));
  }

  static deserialize(data: JWSSerialization): JWS {
    switch (jwsSerializationFormat(data)) {
      case 'compact': {
        const { p_b64u, m, s } = JWSCompactSerializer.deserialize(
          data as JWSSerialization<'compact'>
        );
        const header = JWSHeader.buildFromJWSSerialization(p_b64u);
        return new JWS(m, { header, sig: s });
      }
      case 'json': {
        const { m, hs } = JWSJSONSerializer.deserialize(data as JWSSerialization<'json'>);
        const h = Array.isArray(hs)
          ? hs.map((h) => ({
              header: JWSHeader.buildFromJWSSerialization(h.p_b64u, h.u),
              sig: h.sig,
            }))
          : { header: JWSHeader.buildFromJWSSerialization(hs.p_b64u, hs.u), sig: hs.sig };
        return new JWS(m, h);
      }
      case 'json_flat': {
        const { m, h, s } = JWSFlattenedJSONSerializer.deserialize(
          data as JWSSerialization<'json_flat'>
        );
        return new JWS(m, { header: JWSHeader.buildFromJWSSerialization(h.p_b64u, h.u), sig: s });
      }
    }
  }

  serialize<S extends JWSSerializationFormat>(s: S): JWSSerialization<S> {
    switch (s) {
      case 'compact': {
        if (Array.isArray(this.hs)) {
          throw 'JWS Compact Serialization は複数署名を表現できない';
        }
        const p_b64u = this.hs.header.Protected_b64u();
        if (!p_b64u || this.hs.header.Unprotected()) {
          throw 'JWS Compact Serialization は JWS Unprotected Header を表現できない';
        }
        return JWSCompactSerializer.serialize(p_b64u, this.m, this.hs.sig) as JWSSerialization<S>;
      }
      case 'json': {
        const hs = Array.isArray(this.hs)
          ? this.hs.map((h) => ({
              p_b64u: h.header.Protected_b64u(),
              u: h.header.Unprotected(),
              sig: h.sig,
            }))
          : {
              p_b64u: this.hs.header.Protected_b64u(),
              u: this.hs.header.Unprotected(),
              sig: this.hs.sig,
            };
        return JWSJSONSerializer.serialize(this.m, hs) as JWSSerialization<S>;
      }
      case 'json_flat': {
        if (Array.isArray(this.hs) && this.hs.length > 1) {
          throw 'Flattened JWS JSON Serialization は複数署名を表現できない';
        }
        if (Array.isArray(this.hs)) {
          return JWSFlattenedJSONSerializer.serialize(
            { p_b64u: this.hs[0].header.Protected_b64u(), u: this.hs[0].header.Unprotected() },
            this.m,
            this.hs[0].sig
          ) as JWSSerialization<S>;
        }
        return JWSFlattenedJSONSerializer.serialize(
          { p_b64u: this.hs.header.Protected_b64u(), u: this.hs.header.Unprotected() },
          this.m,
          this.hs.sig
        ) as JWSSerialization<S>;
      }
      default:
        throw TypeError(`${s} はJWSSerialization format ではない`);
    }
  }
}

/**
 * RFC7515#5.1
 * ヘッダーに応じて署名アルゴリズムの選択と、署名鍵を keys から選択する。
 * 署名鍵と署名アルゴリズムを用いて、 JWS Payload と JWS Protected Header に対して署名 or MAC 計算を行い、
 * その結果を返す。
 */
async function sign(keys: JWKSet, m: JWSPayload, h: JWSHeader): Promise<JWSSignature> {
  const input = jwsinput(m, h.Protected_b64u());
  const jh = h.JOSE();
  const alg = jh.alg;
  if (!alg) {
    throw new EvalError('alg が指定されていない');
  }

  switch (JWSOpeModeFromAlg(alg)) {
    case 'None':
      // Unsecured JWS の場合は、署名値がない。
      return new Uint8Array() as JWSSignature;
    case 'Sig': {
      const key = identifyJWK(keys, { ...jh, kty: ktyFromAlg(alg) });
      if (!isJWK(key, 'Priv')) throw new TypeError('公開鍵で署名しようとしている');
      return newSigOperator<typeof alg>(alg).sign(alg, key, input);
    }
    case 'MAC': {
      const key = identifyJWK(keys, { ...jh, kty: ktyFromAlg(alg) });
      return newMacOperator<typeof alg>(alg).mac(alg, key, input);
    }
  }
}

async function verify(
  keys: JWKSet,
  m: JWSPayload,
  h: JWSHeader,
  s?: JWSSignature
): Promise<boolean> {
  const jh = h.JOSE();
  const alg = jh.alg;
  if (!alg) {
    throw new EvalError('alg が指定されていない');
  }

  switch (JWSOpeModeFromAlg(alg)) {
    case 'None':
      return true;
    case 'Sig': {
      if (!s) return false;
      const key = identifyJWK(keys, { ...jh, kty: ktyFromAlg(alg) });
      if (!isJWK(key, 'Pub')) throw new TypeError(`Sig Operator の検証では公開鍵を与えてください`);
      const input = jwsinput(m, h.Protected_b64u());
      return newSigOperator<typeof alg>(alg).verify(alg, key, input, s);
    }
    case 'MAC': {
      if (!s) return false;
      const key = identifyJWK(keys, { ...jh, kty: ktyFromAlg(alg) });
      const input = jwsinput(m, h.Protected_b64u());
      return newMacOperator<typeof alg>(alg).verify(alg, key, input, s);
    }
  }
}

/**
 * RFC7515#2 JWS Signing Input はデジタル署名や MAC の計算に対する入力。
 * この値は、ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))
 */
const jwsinput = (m: JWSPayload, p_b64u?: string): Uint8Array =>
  ASCII((p_b64u ?? '') + '.' + BASE64URL(m));

// --------------------END JWS implementation --------------------
