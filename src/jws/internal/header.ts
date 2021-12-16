// --------------------BEGIN JWS Header definition --------------------

import {
  Alg,
  equalsJOSEHeader,
  isJOSEHeader,
  isJOSEHeaderParamName,
  JOSEHeader,
  JOSEHeaderParamName,
} from 'iana';
import { JWSProtectedHeader, JWSUnprotectedHeader } from 'jws/type';
import { BASE64URL, BASE64URL_DECODE, UTF8, UTF8_DECODE } from 'utility';

export { JWSHeader, JWSHeaderBuilder, JWSHeaderBuilderFromSerializedJWS };

function JWSHeaderBuilderFromSerializedJWS(p_b64u?: string, u?: JWSUnprotectedHeader): JWSHeader {
  let alg: Parameters<typeof JWSHeaderBuilder>[0] | undefined;
  let options: Parameters<typeof JWSHeaderBuilder>[1] | undefined;

  if (p_b64u) {
    const initialValue: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(p_b64u)));
    if (!isJOSEHeader(initialValue, 'JWS')) {
      throw new TypeError('JWS Protected Header の b64u 表現ではなかった');
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
    throw new TypeError('JOSEHeder.alg がなかった');
  }
  return JWSHeaderBuilder(alg, options);
}

function JWSHeaderBuilder(
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
 * JWS では JOSE Header は JWS Protected Header と JWS Unprotected Header の union で表現されるが、
 * 内部構造としてヘッダーパラメータが Protected かどうかという情報を保持し続けるためにクラスで定義している。
 * p と u のいずれか一方は存在することが必要で、どちらかには alg パラメータが含まれている
 */
class JWSHeader {
  private h: JOSEHeader<'JWS'>;
  private readonly p_b64u?: string;
  private paramNames: {
    p: Set<JOSEHeaderParamName<'JWS'>>;
    u: Set<JOSEHeaderParamName<'JWS'>>;
  };

  constructor(
    alg: Alg<'JWS'>,
    options?: {
      p?: {
        initialValue?: JOSEHeader<'JWS'>;
        paramNames?: Set<JOSEHeaderParamName<'JWS'>>;
        b64u?: string;
      };
      u?: {
        initialValue?: JOSEHeader<'JWS'>;
        paramNames?: Set<JOSEHeaderParamName<'JWS'>>;
      };
    }
  ) {
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
              `オプションで指定する ${i}.InitialValue Header と alg の値が一致していない`
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
          if (options.p.initialValue) {
            options.p.initialValue = { ...options.p.initialValue, alg };
          } else {
            options.p.initialValue = { alg };
          }
          if (options.p.paramNames) {
            options.p.paramNames.add('alg');
          }
        } else {
          options.p = { initialValue: { alg } };
        }
      }
    }

    let value: JOSEHeader<'JWS'> = {};
    const paramNames = {
      p: new Set<JOSEHeaderParamName<'JWS'>>(),
      u: new Set<JOSEHeaderParamName<'JWS'>>(),
    };

    for (const i of ['p', 'u'] as const) {
      const h = options[i];
      if (!h) continue;
      // 初期値として与えるヘッダー情報とヘッダー名情報が矛盾していないかチェック
      if (h.initialValue) {
        if (h.paramNames) {
          for (const n of Object.keys(h.initialValue)) {
            if (isJOSEHeaderParamName(n) && !h.paramNames.has(n)) {
              throw new TypeError(
                `オプションで指定する ${i}.Header の初期値と Header Parameter Names が一致していない` +
                  ` because: initValue にあるパラメータ名 ${n} は paramNames ${h.paramNames} に含まれていません`
              );
            }
          }
          h.paramNames.forEach((n) => paramNames[i].add(n));
        } else {
          Object.keys(h.initialValue).forEach((n) => {
            if (isJOSEHeaderParamName(n)) paramNames[i].add(n);
          });
        }
        value = { ...value, ...h.initialValue };
      } else {
        h.paramNames?.forEach((n) => paramNames[i].add(n));
      }
    }

    // オプションで渡される Protected Header の Base64url 表現が JOSE Header のものかチェック
    if (options.p?.b64u) {
      const p: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(options.p.b64u)));
      if (!isJOSEHeader(p, 'JWS')) {
        throw new TypeError(
          'オプションで指定された Protected Header の b64u のデコード結果が JOSE Header for JWE ではなかった'
        );
      }
    }

    // params の整合性チェック。重複していないかどうか判断する
    const params = new Set<JOSEHeaderParamName<'JWE'>>();
    let paramsDesiredSize = 0;
    paramNames.p.forEach((n) => params.add(n));
    paramsDesiredSize += paramNames.p.size;
    paramNames.u.forEach((n) => params.add(n));
    paramsDesiredSize += paramNames.u.size;
    if (paramsDesiredSize !== params.size) {
      throw new TypeError(
        'オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません'
      );
    }

    this.h = value;
    this.paramNames = paramNames;
    return;
  }

  /**
   * JWS Protected Header と JWS Unprotected Header の Union を返す
   */
  JOSE(): JOSEHeader<'JWS'> {
    return this.h;
  }

  /**
   * JWS Protected Header があれば返す。
   */
  Protected(): JWSProtectedHeader | undefined {
    const entries = Object.entries(this.h).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.p.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWSProtectedHeader;
  }

  Protected_b64u(): string | undefined {
    if (this.p_b64u) {
      const p: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(this.p_b64u)));
      if (!isJOSEHeader(p, 'JWS')) {
        throw new TypeError(
          'オプションで指定された Protected Header の b64u のデコード結果が JOSE Header for JWE ではなかった'
        );
      }
      if (!equalsJOSEHeader(p, this.Protected())) {
        throw new TypeError(
          'オプションで指定された Protected Header と生成した Protected Header が一致しなかった' +
            `becasuse: decoded options.b64u: ${p} but generated protected header: ${this.Protected()}`
        );
      }
      return this.p_b64u;
    }
    const p = this.Protected();
    if (p) {
      return BASE64URL(UTF8(JSON.stringify(p)));
    }
    return undefined;
  }

  /**
   * JWS Unprotected Header があれば返す。
   */
  Unprotected(): JWSUnprotectedHeader | undefined {
    const entries = Object.entries(this.h).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.u.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWSUnprotectedHeader;
  }

  update(v: JOSEHeader<'JWS'>) {
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
