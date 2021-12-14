import {
  Alg,
  EncAlg,
  equalsJOSEHeader,
  isJOSEHeader,
  isJOSEHeaderParamName,
  JOSEHeader,
  JOSEHeaderParamName,
} from 'iana';
import {
  JWEPerRecipientUnprotectedHeader,
  JWEProtectedHeader,
  JWESharedUnprotectedHeader,
} from 'jwe/type';
import { BASE64URL, BASE64URL_DECODE, UTF8, UTF8_DECODE } from 'utility';

export { JWEHeader, JWEHeaderBuilder, JWEHeaderBuilderFromSerializedJWE };

function JWEHeaderBuilderFromSerializedJWE(
  p_b64u?: string,
  su?: JWESharedUnprotectedHeader,
  ru?: JWEPerRecipientUnprotectedHeader | Array<JWEPerRecipientUnprotectedHeader | undefined>
): JWEHeader {
  let alg: Parameters<typeof JWEHeaderBuilder>[0];
  let algOne: Alg<'JWE'> | undefined;
  let algArray: Alg<'JWE'>[] | undefined;
  let encalg: Parameters<typeof JWEHeaderBuilder>[1] | undefined;
  let options: Parameters<typeof JWEHeaderBuilder>[2] | undefined;
  if (p_b64u) {
    const initialValue: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(p_b64u)));
    if (!isJOSEHeader(initialValue, 'JWE')) {
      throw new TypeError('JWE Protected Header の b64u 表現ではなかった');
    }
    const paramNames = new Set<JOSEHeaderParamName<'JWE'>>();
    Object.keys(initialValue).forEach((k) => {
      if (isJOSEHeaderParamName(k)) paramNames.add(k);
    });
    if (initialValue.alg) {
      algOne = initialValue.alg;
    }
    if (initialValue.enc) {
      encalg = initialValue.enc;
    }
    if (options) {
      options.p = { initialValue: initialValue as JWEProtectedHeader, paramNames, b64u: p_b64u };
    } else {
      options = {
        p: { initialValue: initialValue as JWEProtectedHeader, paramNames, b64u: p_b64u },
      };
    }
  }
  if (su) {
    const initialValue = su;
    const paramNames = new Set<JOSEHeaderParamName<'JWE'>>();
    Object.keys(initialValue).forEach((k) => {
      if (isJOSEHeaderParamName(k)) paramNames.add(k);
    });
    if (initialValue.alg) {
      algOne = initialValue.alg;
    }
    if (initialValue.enc) {
      encalg = initialValue.enc;
    }
    if (options) {
      options.su = { initialValue, paramNames };
    } else {
      options = { su: { initialValue, paramNames } };
    }
  }
  if (ru) {
    if (Array.isArray(ru)) {
      const ru_option = ru.map((rh) => {
        if (!rh) return {};
        const initialValue = rh;
        const paramNames = new Set<JOSEHeaderParamName<'JWE'>>();
        Object.keys(initialValue).forEach((k) => {
          if (isJOSEHeaderParamName(k)) paramNames.add(k);
        });
        return { initialValue, paramNames };
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
      const paramNames = new Set<JOSEHeaderParamName<'JWE'>>();
      Object.keys(initialValue).forEach((k) => {
        if (isJOSEHeaderParamName(k)) paramNames.add(k);
      });
      if (initialValue.alg) {
        algOne = initialValue.alg;
      }
      if (initialValue.enc) {
        encalg = initialValue.enc;
      }
      if (options) {
        options.ru = { initialValue, paramNames };
      } else {
        options = { ru: { initialValue, paramNames } };
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
    ru?:
      | {
          initialValue?: JWEPerRecipientUnprotectedHeader;
          paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
        }
      | {
          initialValue?: JWEPerRecipientUnprotectedHeader;
          paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
        }[];
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
  JOSE(recipientIndex?: number): JOSEHeader<'JWE'>;
  update(v: JOSEHeader<'JWE'>, recipientIndex?: number): void;
}

class JWEHeaderforMultiParties implements JWEHeader {
  private shared?: JOSEHeader<'JWE'>;
  private readonly protected_b64u?: string;
  private perRecipient: Array<JOSEHeader<'JWE'> | undefined>;
  private paramNames: {
    p: Set<JOSEHeaderParamName<'JWE'>>;
    su: Set<JOSEHeaderParamName<'JWE'>>;
    ru: Set<JOSEHeaderParamName<'JWE'>>[];
  };

  constructor(
    public readonly alg: [Alg<'JWE'>, Alg<'JWE'>, ...Alg<'JWE'>[]],
    public readonly enc: EncAlg,
    options?: {
      p?: {
        initialValue?: JOSEHeader<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
        b64u?: string;
      };
      su?: {
        initialValue?: JOSEHeader<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
      };
      ru?: {
        initialValue?: JOSEHeader<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
      }[];
    }
  ) {
    // オプションの指定がない時は、enc は Protected Header として扱う
    // alg は per recipient unshared header として扱う
    if (!options) {
      this.shared = { enc };
      this.perRecipient = alg.map((a) => ({ alg: a }));
      this.paramNames = {
        p: new Set(['enc']),
        su: new Set(),
        ru: alg.map(() => new Set(['alg'])),
      };
      return;
    }
    let shared: JOSEHeader<'JWE'> | undefined;
    let perRecipient: Array<JOSEHeader<'JWE'> | undefined> = alg.map(() => undefined);
    const paramNames = {
      p: new Set<JOSEHeaderParamName<'JWE'>>(),
      su: new Set<JOSEHeaderParamName<'JWE'>>(),
      ru: alg.map(() => new Set<JOSEHeaderParamName<'JWE'>>()),
    };

    // alg をどのヘッダに組み込むか決定する。また options との整合性をチェック
    if (new Set(alg).size == 1) {
      let isConfigured = false;
      if (options.p?.paramNames?.has('alg')) {
        if (options.p?.initialValue?.alg && options.p.initialValue.alg !== alg[0]) {
          throw new TypeError(
            'オプションで指定する InitialValue for Protected Header と alg の値が一致していない'
          );
        }
        isConfigured = true;
        paramNames.p.add('alg');
        shared = { alg: alg[0] };
      }
      if (options.su?.paramNames?.has('alg')) {
        if (isConfigured) throw new TypeError('alg が重複しています');
        if (options.su?.initialValue?.alg && options.su.initialValue.alg !== alg[0]) {
          throw new TypeError(
            'オプションで指定する InitialValue for Shared Unprotected Header と alg の値が一致していない'
          );
        }
        isConfigured = true;
        paramNames.su.add('alg');
        shared = { alg: alg[0] };
      }
      if (options.ru?.some((o) => o.paramNames?.has('alg'))) {
        if (!options.ru?.every((o) => !o.initialValue?.alg || o.initialValue.alg === alg[0])) {
          throw new TypeError(
            'オプションで指定する InitialValue for PerRecipient Unprotected Header と alg の値が一致していない'
          );
        }
        if (isConfigured) throw new TypeError('alg が重複しています');
        isConfigured = true;
        paramNames.ru.forEach((s) => s.add('alg'));
        perRecipient = perRecipient.map((h, i) => ({ ...h, alg: alg[i] }));
      }
      if (!isConfigured) {
        paramNames.p.add('alg');
        shared = { alg: alg[0] };
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
        if (!options.ru.every((o, i) => !o.initialValue?.alg || o.initialValue.alg === alg[i])) {
          throw new TypeError('オプションで指定する InitialValue と alg の値が一致していない');
        }
      }
      paramNames.ru.forEach((s) => s.add('alg'));
      perRecipient = perRecipient.map((h, i) => ({ ...h, alg: alg[i] }));
    }
    // enc をどのヘッダに組み込むか決定する。
    {
      let isConfigured = false;
      if (options.p?.paramNames?.has('enc')) {
        if (options.p?.initialValue?.enc && options.p.initialValue.enc !== enc) {
          throw new TypeError('オプションで指定する InitialValue と alg の値が一致していない');
        }
        isConfigured = true;
        paramNames.p.add('enc');
        shared = { ...shared, enc };
      }
      if (options.su?.paramNames?.has('enc')) {
        if (isConfigured) throw new TypeError('enc が重複しています');
        if (options.su?.initialValue?.enc && options.su.initialValue.enc !== enc) {
          throw new TypeError('オプションで指定する InitialValue と alg の値が一致していない');
        }
        isConfigured = true;
        paramNames.su.add('enc');
        shared = { ...shared, enc };
      }
      if (options.ru?.some((o) => o.paramNames?.has('enc'))) {
        if (!options.ru?.every((o) => !o.initialValue?.enc || o.initialValue.enc === enc)) {
          throw new TypeError('オプションで指定する InitialValue と enc の値が一致していない');
        }
        if (isConfigured) throw new TypeError('enc が重複しています');
        isConfigured = true;
        paramNames.ru.forEach((s) => s.add('enc'));
        perRecipient.map((rh) => ({ ...rh, enc }));
      }
      if (!isConfigured) {
        paramNames.p.add('enc');
        shared = { ...shared, enc };
      }
    }

    // options で指定されたヘッダごとのパラメータをインスタンスプロパティに与えていく
    for (const i of ['p', 'su'] as const) {
      const h = options[i];
      if (!h) continue;
      // 初期値として与えるヘッダー情報とヘッダー名情報が矛盾していないかチェック
      if (h.initialValue && h.paramNames) {
        for (const n of Object.keys(h.initialValue)) {
          if (isJOSEHeaderParamName(n) && ![...h.paramNames].includes(n)) {
            throw new TypeError(
              'オプションで指定する Header の初期値と Header Parameter Names が一致していない' +
                `because: initValue にあるパラメータ名 ${n} は paramNames ${h.paramNames} に含まれていません`
            );
          }
        }
      }
      shared = { ...shared, ...h.initialValue };
      h.paramNames?.forEach((n) => paramNames[i].add(n));
    }
    if (options.ru) {
      options.ru.forEach((h, i) => {
        // 初期値として与えるヘッダー情報とヘッダー名情報が矛盾していないかチェック
        if (h.initialValue && h.paramNames) {
          for (const n of Object.keys(h.initialValue)) {
            if (isJOSEHeaderParamName(n) && ![...h.paramNames].includes(n)) {
              throw new TypeError(
                'オプションで指定する Header の初期値と Header Parameter Names が一致していない' +
                  `because: initValue にあるパラメータ名 ${n} は paramNames ${h.paramNames} に含まれていません`
              );
            }
          }
        }
        perRecipient = perRecipient.map((rh, i) => ({ ...rh, ...options?.ru?.[i]?.initialValue }));
        options.ru?.forEach((o, i) => o.paramNames?.forEach((n) => paramNames.ru[i].add(n)));
      });
    }

    // オプションで渡される Protected Header の Base64url 表現が JOSE Header のものかチェック
    if (options.p?.b64u) {
      const p: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(options.p.b64u)));
      if (!isJOSEHeader(p, 'JWE')) {
        throw new TypeError(
          'オプションで指定された Protected Header の b64u のデコード結果が JOSE Header for JWE ではなかった'
        );
      }
    }

    // params の整合性チェック。重複していないかどうか判断する
    if (
      !paramNames.ru.every((ru) => {
        const params = new Set([...ru]);
        let paramsDesiredSize = params.size;
        paramNames.p.forEach((n) => params.add(n));
        paramsDesiredSize += paramNames.p.size;
        paramNames.su.forEach((n) => params.add(n));
        paramsDesiredSize += paramNames.su.size;
        return paramsDesiredSize === params.size;
      })
    ) {
      throw new TypeError(
        'オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません'
      );
    }

    this.paramNames = paramNames;
    this.shared = shared;
    this.perRecipient = perRecipient;
    this.protected_b64u = options?.p?.b64u;
  }

  Protected() {
    if (!this.shared) return undefined;
    const entries = Object.entries(this.shared).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.p.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWEProtectedHeader;
  }

  Protected_b64u() {
    if (this.protected_b64u) {
      const p: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(this.protected_b64u)));
      if (!isJOSEHeader(p, 'JWE')) {
        throw new TypeError(
          'オプションで指定された Protected Header の b64u のデコード結果が JOSE Header for JWE ではなかった'
        );
      }
      if (!equalsJOSEHeader(p, this.Protected())) {
        throw new TypeError(
          'オプションで指定された Protected Header と生成した Protected Header が一致しなかった' +
            `becasuse: decoded options.b64u: ${p} but generated protected header: ${this.Protected}`
        );
      }
      return this.protected_b64u;
    }
    if (this.Protected()) {
      return BASE64URL(UTF8(JSON.stringify(this.Protected())));
    }
  }

  SharedUnprotected() {
    if (!this.shared) return undefined;
    const entries = Object.entries(this.shared).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.su.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWESharedUnprotectedHeader;
  }

  PerRecipient(recipientIndex?: number) {
    const idx = recipientIndex ?? 0;
    if (idx > this.perRecipient.length) return undefined;
    const perRcpt = this.perRecipient[idx];
    if (!perRcpt) return undefined;
    const entries = Object.entries(perRcpt).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.ru[idx].has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWEPerRecipientUnprotectedHeader;
  }

  JOSE(recipientIndex?: number) {
    return { ...this.shared, ...this.PerRecipient(recipientIndex) };
  }

  update(v: JOSEHeader<'JWE'>, recipientIndex?: number) {
    const idx = recipientIndex ?? 0;
    if (idx > this.perRecipient.length) return;

    Object.entries(v).forEach(([n, vv]) => {
      if (!isJOSEHeaderParamName(n)) return;
      if (this.paramNames.p.has(n) || this.paramNames.su.has(n)) {
        this.shared = { ...this.shared, [n]: vv };
      }
      if (this.paramNames.ru[idx].has(n)) {
        this.perRecipient[idx] = { ...this.perRecipient[idx], [n]: vv };
      }
      // paramNames で配置場所が指定されていない場合は、 alg と同じ場所
      if (this.paramNames.ru[idx].has('alg')) {
        this.perRecipient[idx] = { ...this.perRecipient[idx], [n]: vv };
        this.paramNames.ru[idx].add(n);
      } else {
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

class JWEHeaderforOne implements JWEHeader {
  private shared?: JOSEHeader<'JWE'>;
  private readonly protected_b64u?: string;
  private perRecipient?: JOSEHeader<'JWE'>;
  private paramNames: {
    p: Set<JOSEHeaderParamName<'JWE'>>;
    su: Set<JOSEHeaderParamName<'JWE'>>;
    ru: Set<JOSEHeaderParamName<'JWE'>>;
  };

  constructor(
    public readonly alg: Alg<'JWE'>,
    public readonly enc: EncAlg,
    options?: {
      p?: {
        initialValue?: JOSEHeader<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
        b64u?: string;
      };
      su?: {
        initialValue?: JOSEHeader<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
      };
      ru?: {
        initialValue?: JOSEHeader<'JWE'>;
        paramNames?: Set<JOSEHeaderParamName<'JWE'>>;
      };
    }
  ) {
    // オプションの指定がない時は、alg と enc はともに Protected Header として扱う
    if (!options) {
      this.shared = { alg, enc };
      this.paramNames = {
        p: new Set(['alg', 'enc']),
        su: new Set(),
        ru: new Set(),
      };
      return;
    }

    const optionParamNames = ['p', 'su', 'ru'] as const;
    for (const i of optionParamNames) {
      const h = options[i];
      if (!h) continue;
      // options.x.initialValue に含まれている情報と alg enc の情報が一致しているかチェック
      if (h.initialValue?.alg && h.initialValue.alg !== alg) {
        throw new TypeError('オプションで指定する InitialValue と alg の値が一致していない');
      }
      if (h.initialValue?.enc && h.initialValue.enc !== enc) {
        throw new TypeError('オプションで指定する InitialValue と enc の値が一致していない');
      }
      // 初期値として与えるヘッダー情報とヘッダー名情報が矛盾していないかチェック
      if (h.initialValue && h.paramNames) {
        for (const n of Object.keys(h.initialValue)) {
          if (isJOSEHeaderParamName(n) && ![...h.paramNames].includes(n)) {
            throw new TypeError(
              'オプションで指定する ProtectedHeader の初期値と Protected Header Parameter Names が一致していない' +
                `because: initValue にあるパラメータ名 ${n} は paramNames ${h.paramNames} に含まれていません`
            );
          }
        }
      }
    }
    // オプションで渡される Protected Header の Base64url 表現が JOSE Header のものかチェック
    if (options.p?.b64u) {
      const p: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(options.p.b64u)));
      if (!isJOSEHeader(p, 'JWE')) {
        throw new TypeError(
          'オプションで指定された Protected Header の b64u のデコード結果が JOSE Header for JWE ではなかった'
        );
      }
    }

    // params の整合性チェック。重複していないかどうか判断する
    const params = new Set<JOSEHeaderParamName<'JWE'>>();
    let paramsDesiredSize = 0;
    for (const i of optionParamNames) {
      const h = options[i];
      if (!h || !h.paramNames) continue;
      h.paramNames.forEach((n) => params.add(n));
      paramsDesiredSize += h.paramNames.size;
    }
    if (paramsDesiredSize !== params.size) {
      throw new TypeError(
        'オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません'
      );
    }

    // options の整合性確認が済んだので、インスタンスを作成
    this.shared = { ...options.p?.initialValue, ...options.su?.initialValue };
    this.perRecipient = { ...options.ru?.initialValue };
    this.protected_b64u = options.p?.b64u;
    this.paramNames = {
      p: options.p?.paramNames ?? new Set(),
      su: options.su?.paramNames ?? new Set(),
      ru: options.ru?.paramNames ?? new Set(),
    };
    // alg を適切なヘッダーパラメータとして保持
    if (this.paramNames.su.has('alg')) {
      this.shared.alg = alg;
    } else if (this.paramNames.ru.has('alg')) {
      this.perRecipient.alg = alg;
    } else {
      // オプションで指定がない時は Protected Header に alg を含める
      this.paramNames.p.add('alg');
      this.shared.alg = alg;
    }
    // enc を適切なヘッダーパラメータとして保持
    if (this.paramNames.su.has('enc')) {
      this.shared.enc = enc;
    } else if (this.paramNames.ru.has('enc')) {
      this.perRecipient.enc = enc;
    } else {
      // オプションで指定がない時は Protected Header に enc を含める
      this.paramNames.p.add('enc');
      this.shared.enc = enc;
    }
  }

  Protected() {
    if (!this.shared) return undefined;
    const entries = Object.entries(this.shared).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.p.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWEProtectedHeader;
  }

  Protected_b64u() {
    if (this.protected_b64u) {
      const p: unknown = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(this.protected_b64u)));
      if (!isJOSEHeader(p, 'JWE')) {
        throw new TypeError(
          'オプションで指定された Protected Header の b64u のデコード結果が JOSE Header for JWE ではなかった'
        );
      }
      if (!equalsJOSEHeader(p, this.Protected())) {
        throw new TypeError(
          'オプションで指定された Protected Header と生成した Protected Header が一致しなかった' +
            `becasuse: decoded options.b64u: ${p} but generated protected header: ${this.Protected}`
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

  SharedUnprotected() {
    if (!this.shared) return undefined;
    const entries = Object.entries(this.shared).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.su.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWESharedUnprotectedHeader;
  }

  PerRecipient() {
    if (!this.perRecipient) return undefined;
    const entries = Object.entries(this.perRecipient).filter(
      ([n]) => isJOSEHeaderParamName(n) && this.paramNames.ru.has(n)
    );
    if (entries.length === 0) return undefined;
    return Object.fromEntries(entries) as JWEPerRecipientUnprotectedHeader;
  }

  JOSE(): JOSEHeader<'JWE'> {
    return { ...this.shared, ...this.perRecipient };
  }

  update(v: JOSEHeader<'JWE'>) {
    Object.entries(v).forEach(([n, vv]) => {
      if (!isJOSEHeaderParamName(n)) return;
      if (this.paramNames.p.has(n) || this.paramNames.su.has(n)) {
        this.shared = { ...this.shared, [n]: vv };
      }
      if (this.paramNames.ru.has(n)) {
        this.perRecipient = { ...this.perRecipient, [n]: vv };
      }
      // paramNames で配置場所が指定されていない場合は、 alg と同じ場所
      if (this.paramNames.ru.has('alg')) {
        this.perRecipient = { ...this.perRecipient, [n]: vv };
        this.paramNames.ru.add(n);
      } else {
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
