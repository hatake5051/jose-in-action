import { Alg, EncAlg } from 'iana/alg';
import {
  equalsJOSEHeaderParams,
  isJOSEHeaderParamName,
  isJOSEHeaderParams,
  JOSEHeaderParamName,
  JOSEHeaderParams,
} from 'iana/header';
import {
  JWEPerRecipientUnprotectedHeader,
  JWEProtectedHeader,
  JWESharedUnprotectedHeader,
} from 'jwe/type';
import { Arrayable, BASE64URL, BASE64URL_DECODE, UTF8, UTF8_DECODE } from 'utility';

export { JWEHeader, JWEHeaderBuilder, JWEHeaderBuilderFromSerializedJWE };

function JWEHeaderBuilderFromSerializedJWE(
  p_b64u?: string,
  su?: JWESharedUnprotectedHeader,
  ru?: Arrayable<JWEPerRecipientUnprotectedHeader | undefined>
): JWEHeader {
  let alg: Parameters<typeof JWEHeaderBuilder>[0];
  let algOne: Alg<'JWE'> | undefined;
  let algArray: Alg<'JWE'>[] | undefined;
  let encalg: Parameters<typeof JWEHeaderBuilder>[1] | undefined;
  let options: Parameters<typeof JWEHeaderBuilder>[2] | undefined;
  if (p_b64u) {
    const initialValue: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(p_b64u)));
    if (!isJOSEHeaderParams(initialValue, 'JWE')) {
      throw new TypeError('JWE Protected Header の b64u 表現ではなかった');
    }
    if (initialValue.alg) {
      algOne = initialValue.alg;
    }
    if (initialValue.enc) {
      encalg = initialValue.enc;
    }
    if (options) {
      options.p = { initialValue: initialValue as JWEProtectedHeader, b64u: p_b64u };
    } else {
      options = {
        p: { initialValue: initialValue as JWEProtectedHeader, b64u: p_b64u },
      };
    }
  }
  if (su) {
    const initialValue = su;
    if (initialValue.alg) {
      algOne = initialValue.alg;
    }
    if (initialValue.enc) {
      encalg = initialValue.enc;
    }
    if (options) {
      options.su = { initialValue };
    } else {
      options = { su: { initialValue } };
    }
  }
  if (ru) {
    if (Array.isArray(ru)) {
      const ru_option = ru.map((rh) => {
        if (!rh) return {};
        const initialValue = rh;
        return { initialValue };
      });
      algArray = ru_option.map(({ initialValue }) => {
        if (initialValue?.enc) {
          encalg = initialValue.enc;
        }
        if (initialValue?.alg) return initialValue?.alg;
        if (algOne) return algOne;
        throw new TypeError('JOSEHeader.alg がない');
      });
      if (options) {
        options.ru = ru_option;
      } else {
        options = { ru: ru_option };
      }
    } else {
      const initialValue = ru;
      if (initialValue.alg) {
        algOne = initialValue.alg;
      }
      if (initialValue.enc) {
        encalg = initialValue.enc;
      }
      if (options) {
        options.ru = { initialValue };
      } else {
        options = { ru: { initialValue } };
      }
    }
  }

  if (!encalg) {
    throw new TypeError('JOSEHeader.enc がなかった');
  }
  if (algOne) {
    alg = algOne;
  } else if (algArray) {
    switch (algArray.length) {
      case 0:
        throw new TypeError('JOSEHeader.alg がなかった');
      case 1: {
        alg = algArray[0];
        break;
      }
      default: {
        alg = [algArray[0], algArray[1], ...algArray.slice(2)];
        break;
      }
    }
  } else {
    throw new TypeError('JOSEHeader.alg がなかった');
  }
  return JWEHeaderBuilder(alg, encalg, options);
}

function JWEHeaderBuilder(
  alg: Alg<'JWE'> | [Alg<'JWE'>, Alg<'JWE'>, ...Alg<'JWE'>[]],
  enc: EncAlg,
  options?: {
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
  }
): JWEHeader {
  if (Array.isArray(alg)) {
    const ru = options?.ru;
    if (ru && !Array.isArray(ru)) {
      throw new TypeError('alg が複数の時、 options.ru も複数にして与えてください');
    }
    return new JWEHeaderforMultiParties(alg, enc, { p: options?.p, su: options?.su, ru });
  }
  const ru = options?.ru;
  if (ru && Array.isArray(ru)) {
    throw new TypeError('alg が単数の時 options.ru も単数にして与えてください');
  }
  return new JWEHeaderforOne(alg, enc, { p: options?.p, su: options?.su, ru });
}

interface JWEHeader {
  Protected(): JWEProtectedHeader | undefined;
  Protected_b64u(): string | undefined;
  SharedUnprotected(): JWESharedUnprotectedHeader | undefined;
  PerRecipient(recipientIndex?: number): JWEPerRecipientUnprotectedHeader | undefined;
  JOSE(recipientIndex?: number): JOSEHeaderParams<'JWE'>;
  update(v: JOSEHeaderParams<'JWE'>, recipientIndex?: number): void;
}

class JWESharedHeader {
  protected shared: JOSEHeaderParams<'JWE'>;
  protected readonly protected_b64u?: string;
  protected paramNames: {
    p: Set<JOSEHeaderParamName<'JWE'>>;
    su: Set<JOSEHeaderParamName<'JWE'>>;
  };

  constructor(options?: {
    p?: {
      initialValue?: JOSEHeaderParams<'JWE'>;
      paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
      b64u?: string;
    };
    su?: {
      initialValue?: JOSEHeaderParams<'JWE'>;
      paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
    };
  }) {
    if (!options) {
      this.shared = {};
      this.paramNames = { p: new Set(), su: new Set() };
      return;
    }

    let shared: JOSEHeaderParams<'JWE'> | undefined;
    const paramNames = {
      p: new Set<JOSEHeaderParamName<'JWE'>>(),
      su: new Set<JOSEHeaderParamName<'JWE'>>(),
    };

    for (const i of ['p', 'su'] as const) {
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
        shared = { ...shared, ...h.initialValue };
      } else {
        h.paramNames?.forEach((n) => paramNames[i].add(n));
      }
    }

    // オプションで渡される Protected Header の Base64url 表現が JOSE Header のものかチェック
    if (options.p?.b64u) {
      const p: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(options.p.b64u)));
      if (!isJOSEHeaderParams(p, 'JWE')) {
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
    paramNames.su.forEach((n) => params.add(n));
    paramsDesiredSize += paramNames.su.size;
    if (paramsDesiredSize !== params.size) {
      throw new TypeError(
        'オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません'
      );
    }

    this.shared = shared ?? {};
    this.paramNames = paramNames;
    return;
  }

  Protected(): JWEProtectedHeader | undefined {
    const entries = Object.entries(this.shared).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.p.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWEProtectedHeader;
  }

  Protected_b64u(): string | undefined {
    if (this.protected_b64u) {
      const p: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(this.protected_b64u)));
      if (!isJOSEHeaderParams(p, 'JWE')) {
        throw new TypeError(
          'オプションで指定された Protected Header の b64u のデコード結果が JOSE Header for JWE ではなかった'
        );
      }
      if (!equalsJOSEHeaderParams(p, this.Protected())) {
        throw new TypeError(
          'オプションで指定された Protected Header と生成した Protected Header が一致しなかった' +
            `becasuse: decoded options.b64u: ${p} but generated protected header: ${this.Protected()}`
        );
      }
      return this.protected_b64u;
    }
    const p = this.Protected();
    if (p) {
      return BASE64URL(UTF8(JSON.stringify(p)));
    }
    return undefined;
  }

  SharedUnprotected(): JWESharedUnprotectedHeader | undefined {
    const entries = Object.entries(this.shared).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.su.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWESharedUnprotectedHeader;
  }

  update(v: JOSEHeaderParams<'JWE'>) {
    Object.entries(v).forEach(([n, vv]) => {
      if (!isJOSEHeaderParamName(n)) return;
      if (this.paramNames.p.has(n) || this.paramNames.su.has(n)) {
        this.shared = { ...this.shared, [n]: vv };
        return;
      }
      // paramNames で配置場所が指定されていない場合は、 alg と同じ場所
      if (this.paramNames.p.has('alg') || this.paramNames.su.has('alg')) {
        this.shared = { ...this.shared, [n]: vv };
        if (this.paramNames.p.has('alg')) {
          this.paramNames.p.add(n);
        } else {
          this.paramNames.su.add(n);
        }
      }
    });
  }
}

class JWEHeaderforMultiParties extends JWESharedHeader implements JWEHeader {
  private perRcpt: Array<{
    params: JOSEHeaderParams<'JWE'>;
    paramNames: Set<JOSEHeaderParamName<'JWE'>>;
  }>;

  constructor(
    alg: [Alg<'JWE'>, Alg<'JWE'>, ...Alg<'JWE'>[]],
    enc: EncAlg,
    options?: {
      p?: {
        initialValue?: JOSEHeaderParams<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
        b64u?: string;
      };
      su?: {
        initialValue?: JOSEHeaderParams<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
      };
      ru?: {
        initialValue?: JOSEHeaderParams<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
      }[];
    }
  ) {
    // オプションの指定がない時は、enc は Protected Header として扱う
    // alg は 全て同じ値であれば Protected Header として、
    // alg が 全て同じ値でないなら PerRecipient Unprotected Header として扱う
    if (!options) {
      if (new Set(alg).size === 1) {
        super({ p: { initialValue: { enc, alg: alg[0] } } });
        this.perRcpt = alg.map(() => ({ params: {}, paramNames: new Set() }));
        return;
      }
      super({ p: { initialValue: { enc } } });
      this.perRcpt = alg.map((a) => ({
        params: { alg: a },
        paramNames: new Set(['alg']),
      }));
      return;
    }

    // alg をどのヘッダに組み込むか決定する。また options との整合性をチェック
    if (new Set(alg).size === 1) {
      let isConfigured = false;
      for (const i of ['p', 'su'] as const) {
        const opt = options[i];
        if (opt?.initialValue?.alg) {
          if (opt.initialValue.alg !== alg[0]) {
            throw new TypeError(
              `オプションで指定する ${i}.InitialValue Header と alg の値が一致していない`
            );
          }
          isConfigured = true;
          continue;
        }
        if (opt?.paramNames?.has('alg')) {
          opt.initialValue = { ...opt.initialValue, alg: alg[0] };
          isConfigured = true;
          continue;
        }
      }
      options.ru?.forEach((r) => {
        if (r.initialValue?.alg) {
          if (r.initialValue.alg !== alg[0]) {
            throw new TypeError(
              `オプションで指定する ru.InitialValue Header と alg の値が一致していない`
            );
          }
          isConfigured = true;
          return;
        }
        if (r.paramNames?.has('alg')) {
          r.initialValue = { ...r.initialValue, alg: alg[0] };
          isConfigured = true;
          return;
        }
      });
      if (!isConfigured) {
        if (options.p) {
          if (options.p.initialValue) {
            options.p.initialValue = { ...options.p.initialValue, alg: alg[0] };
          } else {
            options.p.initialValue = { alg: alg[0] };
          }
          if (options.p.paramNames) {
            options.p.paramNames.add('alg');
          }
        } else {
          options.p = { initialValue: { alg: alg[0] } };
        }
      }
    } else {
      if (options.p?.paramNames?.has('alg') || options.su?.paramNames?.has('alg')) {
        throw new TypeError(
          'alg が同じ値でない時は Protected Header or Shared Unprotected Header に alg パラメータを含めてはならない'
        );
      }
      if (options.ru) {
        if (options.ru.length !== alg.length) {
          throw new TypeError(
            'オプションで PerRecipient Header に関するものを与えるときは alg と同じ長さの配列にしてください。さらに、同じインデックスが同じ受信者を表すようにしてください'
          );
        }
        options.ru.forEach((r, i) => {
          if (r.initialValue?.alg) {
            if (r.initialValue.alg !== alg[i]) {
              throw new TypeError(
                `オプションで指定する ru.InitialValue Header と alg の値が一致していない`
              );
            }
            return;
          }
          if (r.paramNames?.has('alg')) {
            r.initialValue = { ...r.initialValue, alg: alg[0] };
            return;
          }
        });
      } else {
        options.ru = alg.map((a) => ({ initialValue: { alg: a } }));
      }
    }
    // enc をどのヘッダに組み込むか決定する。
    {
      let isConfigured = false;
      for (const i of ['p', 'su'] as const) {
        const opt = options[i];
        if (opt?.initialValue?.enc) {
          if (opt.initialValue.enc !== enc) {
            throw new TypeError(
              `オプションで指定する ${i}.InitialValue Header と enc の値が一致していない`
            );
          }
          isConfigured = true;
          continue;
        }
        if (opt?.paramNames?.has('enc')) {
          opt.initialValue = { ...opt.initialValue, enc: enc };
          isConfigured = true;
          continue;
        }
      }
      options.ru?.forEach((r) => {
        if (r.initialValue?.enc) {
          if (r.initialValue.enc !== enc) {
            throw new TypeError(
              `オプションで指定する ru.InitialValue Header と enc の値が一致していない`
            );
          }
          isConfigured = true;
          return;
        }
        if (r.paramNames?.has('enc')) {
          r.initialValue = { ...r.initialValue, enc };
          isConfigured = true;
          return;
        }
      });
      if (!isConfigured) {
        if (options.p) {
          if (options.p.initialValue) {
            options.p.initialValue = { ...options.p.initialValue, enc };
          } else {
            options.p.initialValue = { enc };
          }
          if (options.p.paramNames) {
            options.p.paramNames.add('alg');
          }
        } else {
          options.p = { initialValue: { enc } };
        }
      }
    }

    // Protected Header と Shared Unprotected Header を保持する JWESharedHeader をインスタンス化
    super(options);

    const perRcpt: Array<{
      params: JOSEHeaderParams<'JWE'>;
      paramNames: Set<JOSEHeaderParamName<'JWE'>>;
    }> = alg.map(() => ({ params: {}, paramNames: new Set() }));

    options.ru?.forEach((r, i) => {
      if (r.initialValue) {
        if (r.paramNames) {
          for (const n of Object.keys(r.initialValue)) {
            if (isJOSEHeaderParamName(n) && !r.paramNames.has(n)) {
              throw new TypeError(
                'オプションで指定する ru.Header の初期値と Header Parameter Names が一致していない' +
                  `because: initValue にあるパラメータ名 ${n} は paramNames ${r.paramNames} に含まれていません`
              );
            }
          }
          r.paramNames.forEach((n) => perRcpt[i].paramNames.add(n));
        } else {
          Object.keys(r.initialValue).forEach((n) => {
            if (isJOSEHeaderParamName(n)) perRcpt[i].paramNames.add(n);
          });
        }
        perRcpt[i].params = { ...perRcpt[i].params, ...r.initialValue };
      } else {
        r.paramNames?.forEach((n) => perRcpt[i].paramNames.add(n));
      }
    });

    // params の整合性チェック。重複していないかどうか判断する
    if (
      !perRcpt.every((pr) => {
        if (pr.paramNames.size === 0) return true;
        const params = new Set([...this.paramNames.p, ...this.paramNames.su]);
        let paramsDesiredSize = this.paramNames.p.size + this.paramNames.su.size;
        pr.paramNames.forEach((n) => params.add(n));
        paramsDesiredSize += pr.paramNames.size;
        return paramsDesiredSize === params.size;
      })
    ) {
      throw new TypeError(
        'オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません'
      );
    }
    this.perRcpt = perRcpt;
  }

  PerRecipient(recipientIndex?: number): JWEPerRecipientUnprotectedHeader | undefined {
    const idx = recipientIndex ?? 0;
    if (idx > this.perRcpt.length) return undefined;
    const entries = Object.entries(this.perRcpt[idx].params).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.perRcpt[idx].paramNames.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWEPerRecipientUnprotectedHeader;
  }

  JOSE(recipientIndex?: number) {
    return { ...this.shared, ...this.PerRecipient(recipientIndex) };
  }

  update(v: JOSEHeaderParams<'JWE'>, recipientIndex?: number) {
    super.update(v);
    const idx = recipientIndex ?? 0;
    if (idx > this.perRcpt.length) return;
    Object.entries(v).forEach(([n, vv]) => {
      if (!isJOSEHeaderParamName(n)) return;
      if (this.perRcpt[idx].paramNames.has(n)) {
        this.perRcpt[idx].params = { ...this.perRcpt[idx].params, [n]: vv };
      }
      // paramNames で配置場所が指定されていない場合は、 alg と同じ場所
      if (this.perRcpt[idx].paramNames.has('alg')) {
        this.perRcpt[idx].params = { ...this.perRcpt[idx].params, [n]: vv };
        this.perRcpt[idx].paramNames.add(n);
      }
    });
  }
}

class JWEHeaderforOne extends JWESharedHeader implements JWEHeader {
  private perRcpt?: {
    params: JOSEHeaderParams<'JWE'>;
    paramNames: Set<JOSEHeaderParamName<'JWE'>>;
  };

  constructor(
    alg: Alg<'JWE'>,
    enc: EncAlg,
    options?: {
      p?: {
        initialValue?: JOSEHeaderParams<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
        b64u?: string;
      };
      su?: {
        initialValue?: JOSEHeaderParams<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
      };
      ru?: {
        initialValue?: JOSEHeaderParams<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
      };
    }
  ) {
    // オプションの指定がない時は、alg と enc はともに Protected Header として扱う
    if (!options) {
      super({ p: { initialValue: { alg, enc } } });
      return;
    }

    // alg と enc をどのヘッダに組み込むか決定する。また options との整合性をチェック
    for (const n of ['alg', 'enc'] as const) {
      let isConfigured = false;
      for (const i of ['p', 'su', 'ru'] as const) {
        const opt = options[i];
        if (opt?.initialValue?.[n]) {
          if (opt.initialValue?.[n] !== (n === 'alg' ? alg : enc)) {
            throw new TypeError(
              `オプションで指定する ${i}.InitialValue と ${n} の値が一致していない`
            );
          }
          isConfigured = true;
          continue;
        }
        if (opt?.paramNames?.has(n)) {
          opt.initialValue = { ...opt.initialValue, [n]: n === 'alg' ? alg : enc };
          isConfigured = true;
        }
      }
      if (!isConfigured) {
        if (options.p) {
          if (options.p.initialValue) {
            options.p.initialValue = { ...options.p.initialValue, [n]: n === 'alg' ? alg : enc };
          } else {
            options.p.initialValue = { [n]: n === 'alg' ? alg : enc };
          }
          if (options.p.paramNames) {
            options.p.paramNames.add(n);
          }
        } else {
          options.p = { initialValue: { [n]: n === 'alg' ? alg : enc } };
        }
      }
    }

    // Protected Header と Shared Unprotected Header を保持する JWESharedHeader をインスタンス化
    super(options);

    let perRcptParams: JOSEHeaderParams<'JWE'> | undefined;
    const perRcptParamNames: Set<JOSEHeaderParamName<'JWE'>> = new Set();

    if (options.ru) {
      const opt = options.ru;
      if (opt.initialValue) {
        if (opt.paramNames) {
          for (const n of Object.keys(opt.initialValue)) {
            if (isJOSEHeaderParamName(n) && !opt.paramNames.has(n)) {
              throw new TypeError(
                'オプションで指定する ru.Header の初期値と Header Parameter Names が一致していない' +
                  `because: initValue にあるパラメータ名 ${n} は paramNames ${opt.paramNames} に含まれていません`
              );
            }
          }
          opt.paramNames.forEach((n) => perRcptParamNames.add(n));
        } else {
          Object.keys(opt.initialValue).forEach((n) => {
            if (isJOSEHeaderParamName(n)) perRcptParamNames.add(n);
          });
        }
        perRcptParams = { ...perRcptParams, ...opt.initialValue };
      } else {
        opt.paramNames?.forEach((n) => perRcptParamNames.add(n));
      }
    }

    // params の整合性チェック。重複していないかどうか判断する
    if (perRcptParamNames.size !== 0) {
      const params = new Set([...this.paramNames.p, ...this.paramNames.su]);
      let paramsDesiredSize = 0;
      perRcptParamNames.forEach((n) => params.add(n));
      paramsDesiredSize += perRcptParamNames.size;
      if (paramsDesiredSize !== params.size) {
        throw new TypeError(
          'オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません'
        );
      }
    }

    // options の整合性確認が済んだので、インスタンスを作成
    if (perRcptParamNames.size !== 0) {
      this.perRcpt = { params: perRcptParams ?? {}, paramNames: perRcptParamNames };
    }
  }

  PerRecipient(): JWEPerRecipientUnprotectedHeader | undefined {
    if (!this.perRcpt) return undefined;
    const entries = Object.entries(this.perRcpt.params).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.perRcpt?.paramNames.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWEPerRecipientUnprotectedHeader;
  }

  JOSE(): JOSEHeaderParams<'JWE'> {
    return { ...this.shared, ...this.PerRecipient() };
  }

  update(v: JOSEHeaderParams<'JWE'>) {
    super.update(v);
    Object.entries(v).forEach(([n, vv]) => {
      if (!isJOSEHeaderParamName(n)) return;
      if (this.perRcpt?.paramNames.has(n)) {
        this.perRcpt.params = { ...this.perRcpt.params, [n]: vv };
      }
      // paramNames で配置場所が指定されていない場合は、 alg と同じ場所
      if (this.perRcpt?.paramNames.has('alg')) {
        this.perRcpt.params = { ...this.perRcpt.params, [n]: vv };
        this.perRcpt.paramNames.add(n);
      }
    });
  }
}
