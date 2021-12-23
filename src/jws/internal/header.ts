// --------------------BEGIN JWS Header definition --------------------

import { Alg } from 'iana/alg';
import {
  equalsJOSEHeaderParams,
  isJOSEHeaderParamName,
  isJOSEHeaderParams,
  JOSEHeaderParamName,
  JOSEHeaderParams,
} from 'iana/header';
import { JWSProtectedHeader, JWSUnprotectedHeader } from 'jws/type';
import { BASE64URL, BASE64URL_DECODE, UTF8, UTF8_DECODE } from 'utility';

export { JWSHeader };

/**
 * JWS において JOSE Header は 一連の Header Parameters からなるが、これらパラメータは JWS Protected Header と
 * JWS Unprotected Header のいずれかに分類される。
 * JWS が複数署名に対応している場合は、 署名操作ごとに一つの JWS Header を用意する必要がある。
 */
class JWSHeader {
  private h: JOSEHeaderParams<'JWS'>;
  private readonly p_b64u?: {
    raw: string;
    json: JOSEHeaderParams<'JWS'>;
  };
  private paramNames: {
    p: Set<JOSEHeaderParamName<'JWS'>>;
    u: Set<JOSEHeaderParamName<'JWS'>>;
  };

  /**
   * JWS Header を構築する。オプションを指定しない場合は、 `alg` は Protected Header として扱われ、 JWS Signature 時に生成された Heade Parameters
   * は `alg` と同じヘッダとして扱う。
   * @param alg JWS Signature 生成アルゴリズムの識別子。
   * @param options ヘッダを構築する上でのオプションを指定する。`p` では Protected Header に関する指定を、
   * `u` では Unprotected Header に関する指定を行う。
   * それぞれは `initialValue` によって初期値を与えることができる。`paramNames` を指定することで、各ヘッダに格納される
   * パラメータを制限できる。`paramNames` を使用する場合は、 `initialValue` に書いたパラメータも含めること。
   * Protected Header に限っては、 `b64u` によって Base64URL 表現を指定することができる。
   * これは JWS Protected Header を base64 url エンコーディングする際に、このインスタンスが持つパラメータと一致するか検証される。
   * @returns JWS Header
   * @throws options が alg や自身で矛盾している場合に TypeError を吐く
   */
  static build(
    alg: Alg<'JWS'>,
    options?: {
      p?: {
        initialValue?: JWSProtectedHeader;
        paramNames?: Set<JOSEHeaderParamName<'JWS'>>;
        b64u?: string;
      };
      u?: {
        initialValue?: JWSUnprotectedHeader;
        paramNames?: Set<JOSEHeaderParamName<'JWS'>>;
      };
    }
  ): JWSHeader {
    return new JWSHeader(alg, options);
  }

  /**
   * JWS Header を JWS Serialization からの情報をもとに構築する。
   * @param p_b64u JWS Protected Header の base64url encoding 表現
   * @param u JWS Unprotected Header の JSON 表現
   * @returns JWS Header
   * @throws options が alg や自身で矛盾している場合に TypeError を吐く
   */
  static buildFromJWSSerialization(p_b64u?: string, u?: JWSUnprotectedHeader): JWSHeader {
    let alg: Parameters<typeof JWSHeader.build>[0] | undefined;
    let options: Parameters<typeof JWSHeader.build>[1] | undefined;

    if (p_b64u) {
      let initialValue: unknown;
      try {
        initialValue = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(p_b64u)));
      } catch (e) {
        throw new TypeError(`p_b64u: ${p_b64u} は JSON の base64url encoding ではない`);
      }
      if (!isJOSEHeaderParams(initialValue, 'JWS')) {
        throw new TypeError(
          `p_b64u: ${p_b64u} は JOSE Header for JWS の base64url encoding ではない`
        );
      }
      if (initialValue.alg) {
        alg = initialValue.alg;
      }
      if (options) {
        options.p = { initialValue: initialValue as JWSProtectedHeader, b64u: p_b64u };
      } else {
        options = {
          p: { initialValue: initialValue as JWSProtectedHeader, b64u: p_b64u },
        };
      }
    }
    if (u) {
      const initialValue = u;
      if (initialValue.alg) {
        alg = initialValue.alg;
      }
      if (options) {
        options.u = { initialValue };
      } else {
        options = { u: { initialValue } };
      }
    }
    if (!alg) {
      throw new TypeError('p_b64u と u を合わせても alg が存在しなかった');
    }
    return new JWSHeader(alg, options);
  }

  private constructor(
    alg: Alg<'JWS'>,
    options?: {
      p?: {
        initialValue?: JOSEHeaderParams<'JWS'>;
        paramNames?: Set<JOSEHeaderParamName<'JWS'>>;
        b64u?: string;
      };
      u?: {
        initialValue?: JOSEHeaderParams<'JWS'>;
        paramNames?: Set<JOSEHeaderParamName<'JWS'>>;
      };
    }
  ) {
    // options の指定がない時は、 protected header に alg を組み込む
    if (!options) {
      this.h = { alg };
      this.paramNames = { p: new Set(['alg']), u: new Set() };
      return;
    }

    // alg をどのヘッダに組み込むか決定する。また options との整合性をチェック
    {
      let isConfigured = false;
      for (const i of ['p', 'u'] as const) {
        const opt = options[i];
        if (opt?.initialValue?.alg) {
          if (opt.initialValue.alg !== alg) {
            throw new TypeError(
              `options.${i}.initialValue.alg: ${opt.initialValue.alg} と ${alg} の値が一致していない`
            );
          }
          isConfigured = true;
          continue;
        }
        if (opt?.paramNames?.has('alg')) {
          opt.initialValue = { ...opt.initialValue, alg };
          isConfigured = true;
          continue;
        }
      }
      if (!isConfigured) {
        if (options.p) {
          options.p.initialValue = { ...options.p.initialValue, alg };
          if (options.p.paramNames) {
            options.p.paramNames.add('alg');
          }
        } else {
          options.p = { initialValue: { alg } };
        }
      }
    }

    // コンストラクタでプロパティに与える情報たち
    let value: JOSEHeaderParams<'JWS'> = {};
    const paramNames = {
      p: new Set<JOSEHeaderParamName<'JWS'>>(),
      u: new Set<JOSEHeaderParamName<'JWS'>>(),
    };

    for (const i of ['p', 'u'] as const) {
      const opt = options[i];
      if (!opt) continue;
      if (!opt.initialValue) {
        opt.paramNames?.forEach((n) => paramNames[i].add(n));
        continue;
      }
      // 初期値として与えるヘッダー情報とヘッダー名情報が矛盾していないかチェック
      if (opt.paramNames) {
        for (const n of Object.keys(opt.initialValue)) {
          if (isJOSEHeaderParamName(n) && !opt.paramNames.has(n)) {
            throw new TypeError(
              `options.${i}.initialValue.${n} に値(${opt.initialValue[n]})があるが options.${i}.paramNames には含まれていない`
            );
          }
        }
        opt.paramNames.forEach((n) => paramNames[i].add(n));
      } else {
        Object.keys(opt.initialValue).forEach((n) => {
          if (isJOSEHeaderParamName(n)) paramNames[i].add(n);
        });
      }
      value = { ...value, ...opt.initialValue };
    }

    // オプションで渡される Protected Header の Base64url 表現が JOSE Header のものかチェック
    if (options.p?.b64u) {
      let p: unknown;
      try {
        p = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(options.p.b64u)));
      } catch (e) {
        throw new TypeError(
          `options.p.b64u: ${options.p.b64u} は JSON の base64url encoding ではない`
        );
      }
      if (!isJOSEHeaderParams(p, 'JWS')) {
        throw new TypeError(
          `options.p.b64u: ${options.p.b64u} は JOSE Header for JWS の base64url encoding ではない`
        );
      }
      this.p_b64u = {
        raw: options.p?.b64u,
        json: p,
      };
    }

    // params の整合性チェック。重複していないかどうか判断する
    {
      const params = new Set<JOSEHeaderParamName<'JWE'>>();
      let paramsDesiredSize = 0;
      for (const n of ['p', 'u'] as const) {
        paramNames[n].forEach((name) => params.add(name));
        paramsDesiredSize += paramNames[n].size;
      }
      if (paramsDesiredSize !== params.size) {
        throw new TypeError(
          'オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません'
        );
      }
    }

    // インスタンスの作成
    this.h = value;
    this.paramNames = paramNames;
    return;
  }

  /**
   * JWS Protected Header と JWS Unprotected Header の Union を返す
   * @returns JOSE Header
   */
  JOSE(): JOSEHeaderParams<'JWS'> {
    return this.h;
  }

  /**
   * JWS Protected Header があれば返す。
   * @returns undefined or JWS Protected Header
   */
  Protected(): JWSProtectedHeader | undefined {
    const entries = Object.entries(this.h).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.p.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWSProtectedHeader;
  }

  /**
   * JWS Protected Header の base64url 表現があれば返す。
   * ヘッダ構成時に base64url 情報を与えていればそれを使う。ただし、このメソッド実行時にこのインスタンスが保有する
   * this.Protected() と内容が一致しない場合は TypeError を吐く
   * @returns undefined or BASE64URL(UTF8(JWS Protected Header))
   * @throws options と矛盾したら TypeError
   */
  Protected_b64u(): string | undefined {
    if (this.p_b64u) {
      if (!equalsJOSEHeaderParams(this.p_b64u.json, this.Protected())) {
        throw new TypeError(
          `オプションで指定された Protected Header(${
            this.p_b64u.raw
          }) と生成した Protected Header(${JSON.stringify(this.Protected())}) が一致しなかった`
        );
      }
      return this.p_b64u.raw;
    }
    const p = this.Protected();
    if (p) {
      return BASE64URL(UTF8(JSON.stringify(p)));
    }
    return undefined;
  }

  /**
   * JWS Unprotected Header があれば返す。
   * @returns undefined or JWS Unprotected Header
   */
  Unprotected(): JWSUnprotectedHeader | undefined {
    const entries = Object.entries(this.h).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.u.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWSUnprotectedHeader;
  }

  /**
   * JWS Header の内容を更新する。（署名生成時生成した検証時に必要なパラメータなど)
   * @param v 更新内容の JOSE Header Parameteres
   */
  update(v: JOSEHeaderParams<'JWS'>) {
    Object.entries(v).forEach(([n, vv]) => {
      if (!isJOSEHeaderParamName(n)) return;
      this.h = { ...this.h, [n]: vv };
      if (this.paramNames.p.has(n) || this.paramNames.u.has(n)) {
        return;
      }
      if (this.paramNames.p.has('alg')) {
        this.paramNames.p.add(n);
      } else {
        this.paramNames.u.add(n);
      }
    });
  }
}

// --------------------END JWS Header definition --------------------
