'use strict';

/**
 * ECDSA アルゴリズムで署名の作成と検証を行うオペレータを定義する
 */
const ECSigOperator = { sign: sign$2, verify: verify$3 };
/**
 * 引数が ECDSA アルゴリズム識別子か確認する。
 */
const isECAlg = (arg) => typeof arg === 'string' && ecAlgList.some((a) => a === arg);
const ecAlgList = ['ES256', 'ES384', 'ES512'];
/**
 * ECDSA (alg)に従い、与えられたメッセージ(m)と秘密鍵(key) から署名を作成する。
 */
async function sign$2(alg, key, m) {
    const { keyAlg, sigAlg } = params$2(alg, key.crv);
    const k = await window.crypto.subtle.importKey('jwk', key, keyAlg, false, ['sign']);
    const s = await window.crypto.subtle.sign(sigAlg, k, m);
    return new Uint8Array(s);
}
/**
 * ECDSA (alg)に従い、与えられたメッセージ(m)と公開鍵(key) を署名(s)で検証する。
 */
async function verify$3(alg, key, m, s) {
    const { keyAlg, sigAlg } = params$2(alg, key.crv);
    const k = await window.crypto.subtle.importKey('jwk', key, keyAlg, false, [
        'verify',
    ]);
    const sig = await window.crypto.subtle.verify(sigAlg, k, s, m);
    return sig;
}
function params$2(alg, crv) {
    return {
        keyAlg: { name: 'ECDSA', namedCurve: crv },
        sigAlg: { name: 'ECDSA', hash: 'SHA-' + alg.slice(2) },
    };
}
// --------------------END JWA EC algorithms --------------------

// --------------------BEGIN util functions --------------------
/**
 * 文字列を UTF8 バイトエンコードする。(string to Uint8Array)
 */
function UTF8(STRING) {
    const encoder = new TextEncoder();
    return encoder.encode(STRING);
}
/**
 * 文字列に UTF8 バイトデコードする (Uint8Array to string)
 */
function UTF8_DECODE(OCTETS) {
    const decoder = new TextDecoder();
    return decoder.decode(OCTETS);
}
/**
 * 文字列を ASCII バイトエンコードする。 (string to Uint8Array)
 */
function ASCII(STRING) {
    const b = new Uint8Array(STRING.length);
    for (let i = 0; i < STRING.length; i++) {
        b[i] = STRING.charCodeAt(i);
    }
    return b;
}
/**
 * バイト列を BASE64URL エンコードする (Uint8Array to string)
 */
function BASE64URL(OCTETS) {
    // window 組み込みの base64 encode 関数
    // 組み込みの関数は引数としてバイナリ文字列を要求するため
    // Uint8Array をバイナリ文字列へと変換する
    const b_str = String.fromCharCode(...OCTETS);
    const base64_encode = window.btoa(b_str);
    return (base64_encode
        // 文字「+」は全て「-」へ変換する
        .replaceAll('+', '-')
        // 文字「/」は全て「_」へ変換する
        .replaceAll('/', '_')
        // 4の倍数にするためのパディング文字は全て消去
        .replaceAll('=', ''));
}
/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
 */
function BASE64URL_DECODE(STRING) {
    const url_decode = STRING
        // URL-safe にするために変換した文字たちを戻す
        .replaceAll('-', '+')
        .replaceAll('_', '/')
        // 文字列長が4の倍数になるように padding文字で埋める
        .padEnd(Math.ceil(STRING.length / 4) * 4, '=');
    // window 組み込みの base64 decode 関数
    // この関数はデコードの結果をバイナリ文字列として出力する
    const b_str = window.atob(url_decode);
    // バイナリ文字列を Uint8Array に変換する
    const b = new Uint8Array(b_str.length);
    for (let i = 0; i < b_str.length; i++) {
        b[i] = b_str.charCodeAt(i);
    }
    return b;
}
/**
 * ２つのバイト列を結合する
 */
function CONCAT(A, B) {
    const ans = new Uint8Array(A.length + B.length);
    ans.set(A);
    ans.set(B, A.length);
    return ans;
}
/**
 * value を WouldBE<T> かどうか判定する。
 * T のプロパティを持つかもしれないところまで。
 */
const isObject = (value) => typeof value === 'object' && value !== null;
// --------------------END util functions --------------------

/**
 * HMAC アルゴリズムで MAC の生成と検証を行うオペレータを定義する
 */
const HMACOperator = { mac, verify: verify$2 };
/**
 * 引数が HMAC アルゴリズム識別子か確認する。
 */
const isHSAlg = (arg) => typeof arg === 'string' && hsAlgList.some((a) => a === arg);
const hsAlgList = ['HS256', 'HS384', 'HS512'];
/**
 * HMAC アルゴリズムに従い MAC を計算する。
 * 計算を行う前に、鍵長が十分かどうか判定を行う。
 */
async function mac(alg, key, m) {
    // ハッシュの出力サイズ以上の鍵長が必要である (RFC8517#3.2)
    if (BASE64URL_DECODE(key.k).length < parseInt(alg.slice(2)) / 8) {
        throw new EvalError(`${alg} では鍵長が ${parseInt(alg.slice(2)) / 8} 以上にしてください`);
    }
    const { k: keyAlg, s: sigAlg } = params$1(alg);
    const k = await window.crypto.subtle.importKey('jwk', key, keyAlg, false, ['sign']);
    const s = await window.crypto.subtle.sign(sigAlg, k, m);
    return new Uint8Array(s);
}
/**
 * HMAC アルゴリズムに従い、与えられた MAC を検証する。
 */
async function verify$2(alg, key, m, s) {
    // ハッシュの出力サイズ以上の鍵長が必要である (RFC8517#3.2)
    if (BASE64URL_DECODE(key.k).length < parseInt(alg.slice(2)) / 8) {
        throw new EvalError(`${alg} では鍵長が ${parseInt(alg.slice(2)) / 8} 以上にしてください`);
    }
    const { k: keyAlg, s: sigAlg } = params$1(alg);
    const k = await window.crypto.subtle.importKey('jwk', key, keyAlg, false, [
        'verify',
    ]);
    const isValid = await window.crypto.subtle.verify(sigAlg, k, s, m);
    return isValid;
}
function params$1(alg) {
    const name = 'HMAC';
    const keyAlg = { name, hash: 'SHA-' + alg.slice(2) };
    const sigAlg = name;
    return { k: keyAlg, s: sigAlg };
}
// --------------------END JWA HMAC algorithms --------------------

/**
 * RSASSA-PKCS1-v1.5 か RSA-PSS アルゴリズムで署名の作成と検証を行うオペレータを定義する
 */
const RSASigOperator = {
    sign: sign$1,
    verify: verify$1,
};
/**
 * 引数が RSA-PKCS1-v1.5 アルゴリズム識別子か確認する。
 */
const isRSAlg = (arg) => typeof arg === 'string' && rsAlgList.some((a) => a === arg);
const rsAlgList = ['RS256', 'RS384', 'RS512'];
/**
 * 引数が RSA-PSS アルゴリズム識別子か確認する。
 */
const isPSAlg = (arg) => typeof arg === 'string' && psAlgList.some((a) => a === arg);
const psAlgList = ['PS256', 'PS384', 'PS512'];
/**
 * RSASSA-PKCS1-v1.5 か RSA-PSS アルゴリズム(alg)に従い、与えられたメッセージ(m)と秘密鍵(key) から署名を作成する。
 * 計算を行う前に、鍵長が十分かどうか判定を行う。
 */
async function sign$1(alg, key, m) {
    const { keyAlg, sigAlg } = params(alg);
    if (BASE64URL_DECODE(key.n).length * 8 < 2048 && BASE64URL_DECODE(key.d).length * 8 < 2048) {
        // キーサイズが 2048 bit 以上であることが MUST (RFC7518#3.3)
        throw new EvalError(`RSA sig では鍵長が 2048 以上にしてください`);
    }
    const k = await window.crypto.subtle.importKey('jwk', key, keyAlg, false, ['sign']);
    const s = await window.crypto.subtle.sign(sigAlg, k, m);
    return new Uint8Array(s);
}
/**
 * RSASSA-PKCS1-v1.5 か RSA-PSS アルゴリズム(alg)に従い、与えられたメッセージ(m)と公開鍵(key) を署名(sig)で検証する。
 * 計算を行う前に、鍵長が十分かどうか判定を行う。
 */
async function verify$1(alg, key, m, sig) {
    if (BASE64URL_DECODE(key.n).length * 8 < 2048) {
        // キーサイズが 2048 bit 以上であることが MUST (RFC7518#3.3)
        throw new EvalError(`RSA sig では鍵長が 2048 以上にしてください`);
    }
    const { keyAlg, sigAlg } = params(alg);
    const k = await window.crypto.subtle.importKey('jwk', key, keyAlg, false, [
        'verify',
    ]);
    const s = await window.crypto.subtle.verify(sigAlg, k, sig, m);
    return s;
}
function params(alg) {
    let name, sigAlg;
    if (isRSAlg(alg)) {
        name = 'RSASSA-PKCS1-v1_5';
        sigAlg = name;
    }
    else {
        // isPSAlg(alg) === true
        name = 'RSA-PSS';
        // ソルト値のサイズはハッシュ関数の出力と同じサイズ (RFC7518#3.5)
        sigAlg = { name, saltLength: parseInt(alg.slice(2)) / 8 };
    }
    const keyAlg = { name, hash: 'SHA-' + alg.slice(2) };
    return { keyAlg, sigAlg };
}
// --------------------END JWA RSA algorithms --------------------

const isJWASigAlg = (arg) => isRSAlg(arg) || isPSAlg(arg) || isECAlg(arg);
/**
 * JWA で定義されている署名アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newJWASigOperator(alg) {
    if (isRSAlg(alg) || isPSAlg(alg))
        return RSASigOperator;
    if (isECAlg(alg))
        return ECSigOperator;
    throw new TypeError(`SigOperator<${alg}> は実装されていない`);
}
/**
 * 引数が JWS の MAC アルゴリズムか確認する
 */
const isJWAMACAlg = (arg) => isHSAlg(arg);
/**
 * MAC アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newJWAMACOperator(alg) {
    if (isHSAlg(alg))
        return HMACOperator;
    throw TypeError(`MacOperator<${alg}> は実装されていない`);
}
/**
 * JWS Alg に応じた Kty を返す。
 */
function ktyFromJWAJWSAlg(alg) {
    if (isPSAlg(alg) || isRSAlg(alg))
        return 'RSA';
    if (isECAlg(alg))
        return 'EC';
    if (isHSAlg(alg))
        return 'oct';
    throw new TypeError(`${alg} は JWA で定義された JWS の Alg ではない`);
}
// --------------------END JWA JWS algorithms --------------------

// --------------------BEGIN JWA Kty and Crv definition --------------------
const isJWAKty = (arg) => typeof arg == 'string' && jwaKtyList.some((k) => k === arg);
const jwaKtyList = ['EC', 'RSA', 'oct'];
const isJWACrv = (arg) => typeof arg === 'string' && jwaCrvList.some((u) => u === arg);
const jwaCrvList = ['P-256', 'P-384', 'P-521'];
// --------------------BEGIN JWA Kty and Crv definition --------------------

// --------------------BEGIN iana constants --------------------
const algList = [
    'RSA1_5',
    'RSA-OAEP',
    'RSA-OAEP-256',
    'A128KW',
    'A192KW',
    'A256KW',
    'dir',
    'ECDH-ES',
    'ECDH-ES+A128KW',
    'ECDH-ES+A192KW',
    'ECDH-ES+A256KW',
    'A128GCMKW',
    'A192GCMKW',
    'A256GCMKW',
    'PBES2-HS256+A128KW',
    'PBES2-HS384+A192KW',
    'PBES2-HS512+A256KW',
];
const isAlg = (arg) => {
    if (isJWASigAlg(arg) || isJWAMACAlg(arg))
        return true;
    if (typeof arg === 'string') {
        if (arg === 'none')
            return true;
        return algList.some((a) => a === arg);
    }
    return false;
};
const isKty = (arg) => isJWAKty(arg);
const keyUseList = ['sig', 'enc'];
const isKeyUse = (arg) => {
    if (typeof arg === 'string') {
        return keyUseList.some((u) => u === arg);
    }
    return false;
};
/**
 * JSON Web Key Operations を列挙する。
 */
const keyOpsList = [
    'sign',
    'verify',
    'encrypt',
    'decrypt',
    'wrapKey',
    'unwrapKey',
    'deriveKey',
    'deriveBits',
];
const isKeyOps = (arg) => {
    if (typeof arg === 'string') {
        return keyOpsList.some((u) => u === arg);
    }
    return false;
};
// --------------------END iana constants --------------------

// --------------------BEGIN JWK common parameters --------------------
const commonJWKParamNameList = [
    'kty',
    'use',
    'key_ops',
    'alg',
    'kid',
    'x5u',
    'x5c',
    'x5t',
    'x5t#S256',
];
/**
 * CommonJWKParams の型ガード。型で表現していない JWK の制限は validJWK でチェックする。
 */
const isCommonJWKParams = (arg) => isObject(arg) &&
    commonJWKParamNameList.every((n) => {
        if (arg[n] == null)
            return true;
        switch (n) {
            case 'kty':
                return isKty(arg[n]);
            case 'use':
                return isKeyUse(arg[n]);
            case 'key_ops':
                return isKeyOps(arg[n]);
            case 'alg':
                return isAlg(arg[n]);
            case 'x5c':
                return Array.isArray(arg['x5c']) && arg['x5c'].every((s) => typeof s === 'string');
            default:
                return typeof arg[n] === 'string';
        }
    });
function equalsCommonJWKParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    for (const n of commonJWKParamNameList) {
        const ln = l[n];
        const rn = r[n];
        if (ln == null && rn == null)
            continue;
        if (ln == null || rn == null)
            return false;
        switch (n) {
            case 'key_ops':
            case 'x5t': {
                const ll = ln;
                const rr = rn;
                if (new Set(ll).size === new Set(rr).size && ll.every((l) => rr.includes(l)))
                    continue;
                return false;
            }
            default: {
                const ll = ln;
                const rr = rn;
                if (ll === rr)
                    continue;
                return false;
            }
        }
    }
    return true;
}
/**
 * CommonJWKParams が RFC7517 に準拠しているか確認する
 */
function validCommonJWKParams(params) {
    if (params.key_ops != null) {
        // key_ops と use は一緒に使うべきではない (SHOULD NOT)
        if (params.use != null)
            return false;
        const set = new Set(params.key_ops);
        // key_ops は高々２の配列で、重複する値を含めてはならない(MUST NOT)
        if (params.key_ops.length > 2 || params.key_ops.length !== set.size)
            return false;
        if (set.size === 2) {
            // かつ、要素は["sign", "verify"], ["encrypt", "decrypt"], ["wrapKey", "unwrapKey"] のバリエーションのみ(SHOULD)
            // 疑問: なぜ ["deriveBit", "deriveKey"] の組み合わせはなぜダメなのか？教えて欲しい...
            if (!((set.has('sign') && set.has('verify')) ||
                (set.has('encrypt') && set.has('decrypt')) ||
                (set.has('wrapKey') && set.has('unwrapKey'))))
                return false;
        }
    }
    return true;
}
// --------------------END JWK common parameters --------------------

// --------------------BEGIN JWA EC keys --------------------
/**
 * 引数が EC公開鍵の JWK 表現か確認する。
 * kty == EC かどうか、 crv に適した x,y のサイズとなっているかどうか。
 */
const isECPublicKey = (arg) => isCommonJWKParams(arg) &&
    arg.kty === 'EC' &&
    isECPublicKeyParams(arg) &&
    validECPublicKeyParams(arg);
function equalsECPublicKey(l, r) {
    return equalsCommonJWKParams(l, r) && equalsECPublicKeyParams(l, r);
}
/**
 * 引数が EC 秘密鍵の JWK 表現か確認する。
 * EC 公開鍵であり、かつ d をパラメータとして持っていれば。
 */
const isECPrivateKey = (arg) => isECPublicKey(arg) && isECPrivateKeyParams(arg) && validECPrivateKeyParams(arg.crv, arg);
function equalsECPrivateKey(l, r) {
    if (!equalsECPublicKey(l, r))
        return false;
    return l?.d === r?.d;
}
const exportECPublicKey = (priv) => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { d, ...pub } = priv;
    return pub;
};
const ecPublicKeyParams = ['crv', 'x', 'y'];
const isECPublicKeyParams = (arg) => isObject(arg) &&
    isJWACrv(arg.crv) &&
    typeof arg.x === 'string' &&
    typeof arg.x === 'string';
/**
 * EC 公開鍵パラメータが矛盾した値になってないか確認する
 */
function validECPublicKeyParams(p) {
    let key_len;
    switch (p.crv) {
        case 'P-256':
            key_len = 32;
            break;
        case 'P-384':
            key_len = 48;
            break;
        case 'P-521':
            key_len = 66;
            break;
    }
    return BASE64URL_DECODE(p.x).length === key_len && BASE64URL_DECODE(p.y).length === key_len;
}
function equalsECPublicKeyParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    for (const n of ecPublicKeyParams) {
        const ln = l[n];
        const rn = r[n];
        if (ln == null && rn == null)
            continue;
        if (ln == null || rn == null)
            return false;
        if (ln === rn)
            continue;
        return false;
    }
    return true;
}
const isECPrivateKeyParams = (arg) => isObject(arg) && typeof arg.d === 'string';
/**
 * EC 秘密鍵パラメータが引数で与えた crv のものか確認する。
 */
function validECPrivateKeyParams(crv, p) {
    let key_len;
    switch (crv) {
        case 'P-256':
            key_len = 32;
            break;
        case 'P-384':
            key_len = 48;
            break;
        case 'P-521':
            key_len = 66;
            break;
    }
    return BASE64URL_DECODE(p.d).length === key_len;
}
// --------------------END JWA EC keys --------------------

// --------------------BEGIN JWA symmetric keys --------------------
/**
 * 引数が対称鍵か確認する。
 * kty == oct で k をパラメータとして持つか確認する。
 */
const isOctKey = (arg) => isCommonJWKParams(arg) && arg.kty === 'oct' && isoctKeyParams(arg);
function equalsOctKey(l, r) {
    if (!equalsCommonJWKParams(l, r))
        return false;
    return l?.k === r?.k;
}
const isoctKeyParams = (arg) => isObject(arg) && typeof arg.k === 'string';
// --------------------END JWA symmetric keys --------------------

// --------------------BEGIN JWA RSA keys --------------------
/**
 * 引数が RSA 公開鍵かどうか確認する。
 * kty == RSA かどうか、 n,e をパラメータとしてもつか確認する。
 */
const isRSAPublicKey = (arg) => isCommonJWKParams(arg) && arg.kty === 'RSA' && isRSAPublicKeyParams(arg);
function equalsRSAPublicKey(l, r) {
    return equalsCommonJWKParams(l, r) && equalsRSAPublicKeyParams(l, r);
}
/**
 * 引数が RSA 秘密鍵かどうか確認する。
 * RSA 公開鍵であるか、また d をパラメータとして持つか確認する。
 */
const isRSAPrivateKey = (arg) => isRSAPublicKey(arg) && isRSAPrivateKeyParams(arg);
function equalsRSAPrivateKey(l, r) {
    return equalsRSAPublicKey(l, r) && equalsRSAPrivateKeyParams(l, r);
}
const exportRSAPublicKey = (priv) => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { d, p, q, dp, dq, qi, ...pub } = priv;
    return pub;
};
const rsaPublicKeyParams = ['n', 'e'];
const isRSAPublicKeyParams = (arg) => isObject(arg) && typeof arg.n === 'string' && typeof arg.e === 'string';
function equalsRSAPublicKeyParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    for (const n of rsaPublicKeyParams) {
        const ln = l[n];
        const rn = r[n];
        if (ln == null && rn == null)
            continue;
        if (ln == null || rn == null)
            return false;
        if (ln === rn)
            continue;
        return false;
    }
    return true;
}
const rsaPrivateParams = ['d', 'p', 'q', 'dp', 'dq', 'qi'];
const isRSAPrivateKeyParams = (arg) => isObject(arg) &&
    rsaPrivateParams.every((n) => n === 'd' ? typeof arg[n] === 'string' : arg[n] == null || typeof arg[n] === 'string');
function equalsRSAPrivateKeyParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    for (const n of rsaPrivateParams) {
        const ln = l[n];
        const rn = r[n];
        if (ln == null && rn == null)
            continue;
        if (ln == null || rn == null)
            return false;
        if (ln === rn)
            continue;
        return false;
    }
    return true;
}
// --------------------END JWA RSA keys --------------------

// --------------------BEGIN JWA JWK definition --------------------
function isJWAJWK(arg, kty, asym) {
    switch (kty) {
        case 'oct':
            return isOctKey(arg);
        case 'EC':
            if (asym === undefined)
                return isECPublicKey(arg) || isECPrivateKey(arg);
            if (asym === 'Pub')
                return isECPublicKey(arg);
            return isECPrivateKey(arg);
        case 'RSA':
            if (asym === undefined)
                return isRSAPublicKey(arg) || isRSAPrivateKey(arg);
            if (asym === 'Pub')
                return isRSAPublicKey(arg);
            return isRSAPrivateKey(arg);
        default:
            return false;
    }
}
function equalsJWAJWK(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    switch (l.kty) {
        case 'oct':
            return r.kty === 'oct' && equalsOctKey(l, r);
        case 'RSA': {
            if (r.kty !== 'RSA')
                return false;
            if (isRSAPrivateKey(l)) {
                if (isRSAPrivateKey(r))
                    return equalsRSAPrivateKey(l, r);
                return false;
            }
            if (isRSAPrivateKey(r))
                return false;
            return equalsRSAPublicKey(l, r);
        }
        case 'EC': {
            if (r.kty !== 'EC')
                return false;
            if (isECPrivateKey(l)) {
                if (isECPrivateKey(r))
                    return equalsECPrivateKey(l, r);
                return false;
            }
            if (isECPrivateKey(r))
                return false;
            return equalsECPublicKey(l, r);
        }
    }
}
/**
 * 秘密鍵から公開鍵情報を取り出す。
 */
function exportJWAPublicKey(priv) {
    switch (priv.kty) {
        case 'RSA':
            return exportRSAPublicKey(priv);
        case 'EC':
            return exportECPublicKey(priv);
    }
}
// --------------------END JWA JWK definition --------------------

// --------------------BEGIN X.509 DER praser --------------------
/**
 * 自己署名証明書の X.509 証明書を受け取って、有効性の検証を行う。
 * ここで行う有効性の検証は TBSCertificate.signature に書かれてあるアルゴリズムを使って、
 * TBSCertificate.subjectPublicKeyInfo の公開鍵を用いて Certificate.signatureValue
 * の検証ができるかのみを行う。
 * validity の検証など必要な様々な検証が未実装である。
 */
async function validateSelfSignedCert(crt) {
    // alg を識別する
    const alg = crt.sigAlg;
    if (alg !== crt.tbs.alg) {
        throw EvalError('signatureAlgorithm !== TBSCertificate.signature エラー');
    }
    // for Public-Key Cryptography Standards (PKCS) OID
    if (alg.startsWith('1.2.840.113549.1.1')) {
        let keyAlg;
        const verifyAlg = 'RSASSA-PKCS1-v1_5';
        switch (alg) {
            // sha1-with-rsa-signature とか sha1WithRSAEncryption
            case '1.2.840.113549.1.1.5':
                keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' };
                break;
            // sha256WithRSAEncryption
            case '1.2.840.113549.1.1.11':
                keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
                break;
            default:
                throw EvalError(`unimplemented rsa alg(${alg})`);
        }
        const pubkey = await crypto.subtle.importKey('spki', crt.tbs.spki.raw, keyAlg, false, [
            'verify',
        ]);
        return crypto.subtle.verify(verifyAlg, pubkey, crt.sig, crt.tbs.raw);
    }
    // OID(ansi-X9-62 signatures) は ecdsa の署名アルゴリズムを識別する
    if (alg.startsWith('1.2.840.10045.4')) {
        let keyAlg;
        let verifyAlg;
        switch (alg) {
            // ecdsa-with-SHA256 (RFC5480)
            case '1.2.840.10045.4.3.2':
                keyAlg = { name: 'ECDSA', namedCurve: 'P-256' };
                verifyAlg = { name: 'ECDSA', hash: 'SHA-256' };
                break;
            // ecdsa-with-SHA384
            case '1.2.840.10045.4.3.3':
                keyAlg = { name: 'ECDSA', namedCurve: 'P-384' };
                verifyAlg = { name: 'ECDSA', hash: 'SHA-384' };
                break;
            // ecdsa-with-SHA512
            case '1.2.840.10045.4.3.4':
                keyAlg = { name: 'ECDSA', namedCurve: 'P-521' };
                verifyAlg = { name: 'ECDSA', hash: 'SHA-512' };
                break;
            default:
                throw EvalError(`unimplemented ec alg(${alg})`);
        }
        const pubkey = await crypto.subtle.importKey('spki', crt.tbs.spki.raw, keyAlg, false, [
            'verify',
        ]);
        return crypto.subtle.verify(verifyAlg, pubkey, crt.sig, crt.tbs.raw);
    }
    throw EvalError(`unimplemented alg(${alg})`);
}
/**
 * X.509 Certificate を表す、BASE64 エンコードされた DER をパースする
 */
function parseX509BASE64EncodedDER(der_b64) {
    return parseX509DER(BASE64_DECODE(der_b64));
}
function parseX509DER(der_raw) {
    const der = DER_DECODE(der_raw);
    if (der.class !== 'Universal' || der.pc !== 'Constructed' || der.tag !== TAG_SEQUENCE) {
        throw EvalError('X509Cert DER フォーマットを満たしていない');
    }
    const seq = derArrayFromSEQUENCE(der);
    if (seq.length !== 3) {
        throw EvalError('X509Cert DER format を満たしていない');
    }
    const tbs_der = seq[0];
    // AlgorithmIdentifier は以下の通りで、 RSA-PKCSv1.5 と ECDSA では parameter が null
    // SEQUENCE  {
    //   algorithm               OBJECT IDENTIFIER,
    //   parameters              ANY DEFINED BY algorithm OPTIONAL  }
    const alg_der = derArrayFromSEQUENCE(seq[1])[0];
    const sigAlg = convertDotNotationFromOID(alg_der);
    const sig_der = seq[2];
    let sig;
    switch (sigAlg) {
        // shaXXXWithRSAEncryption
        case '1.2.840.113549.1.1.5':
        case '1.2.840.113549.1.1.11':
            sig = extractBytesFromBITSTRING(sig_der);
            break;
        // ecdsa-with-SHAXXX の時は
        // Ecdsa-Sig-Value  ::=  SEQUENCE  { r INTEGER, s INTEGER }
        case '1.2.840.10045.4.3.2':
        case '1.2.840.10045.4.3.3':
        case '1.2.840.10045.4.3.4': {
            const [r, s] = derArrayFromSEQUENCE(DER_DECODE(extractBytesFromBITSTRING(sig_der)));
            // JWS などでサポートする署名値 format は r と s のバイナリ表現を単にくっつけただけのやつ
            sig = CONCAT(extractNonNegativeIntegerFromInteger(r), extractNonNegativeIntegerFromInteger(s));
            break;
        }
        default:
            throw EvalError(`parseX509DER does not support this alg(${sigAlg})`);
    }
    return { tbs: parseX509TBSCert(tbs_der), sigAlg, sig };
}
/**
 * X509 tbsCertificate の DER 表現をパースする
 *  TBSCertificate  ::=  SEQUENCE  {
 *         version         [0]  EXPLICIT Version DEFAULT v1,
 *         serialNumber         CertificateSerialNumber,
 *         signature            AlgorithmIdentifier,
 *         issuer               Name,
 *         validity             Validity,
 *         subject              Name,
 *         subjectPublicKeyInfo SubjectPublicKeyInfo,
 *         issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
 *         subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
 *         extensions      [3]  EXPLICIT Extensions OPTIONAL        -- If present, version MUST be v3        }
 */
function parseX509TBSCert(der) {
    // TBSCert は SEQUENCE で表される
    if (der.class !== 'Universal' || der.pc !== 'Constructed' || der.tag !== TAG_SEQUENCE) {
        throw EvalError('X509TBSCert DER フォーマットを満たしていない');
    }
    const seq = derArrayFromSEQUENCE(der);
    // Version は省略されるかもしれない (その場合は古いバージョンなのでエラーにする)
    if (seq[0].class !== 'ContentSpecific') {
        throw EvalError('X509v3 certificate ではない');
    }
    return {
        raw: der.raw,
        alg: convertDotNotationFromOID(DER_DECODE(seq[2].value)),
        spki: parseX509SPKI(seq[6]),
    };
}
const isX509SPKI = (arg, kty) => {
    if (typeof arg !== 'object')
        return false;
    if (arg == null)
        return false;
    if ('kty' in arg) {
        const a = arg;
        if (typeof a.kty !== 'string')
            return false;
        if (kty !== a.kty)
            return false;
        switch (a.kty) {
            case 'RSA':
                return 'raw' in a && 'n' in a && 'e' in a;
            case 'EC':
                return 'raw' in a && 'x' in a && 'y' in a;
            default:
                throw TypeError(`isX509SPKI(${kty}) is not implemented`);
        }
    }
    return false;
};
function parseX509SPKI(der) {
    if (der.class !== 'Universal' || der.pc !== 'Constructed' || der.tag !== TAG_SEQUENCE) {
        throw EvalError('SubjectPublicKeyInfo DER フォーマットを満たしていない');
    }
    const [algID, spki] = derArrayFromSEQUENCE(der);
    const [alg, param] = derArrayFromSEQUENCE(algID);
    switch (convertDotNotationFromOID(alg)) {
        // このOID(rsaEncryption) は RSA 公開鍵を識別する (RFC3279)
        case '1.2.840.113549.1.1.1': {
            // パラメータは null である
            if (param.class !== 'Universal' || param.tag !== TAG_NULL) {
                throw EvalError('RSA公開鍵のフォーマットを満たしていない');
            }
            // spki は次のフォーマットになる (RFC3279)
            // RSAPublicKey ::= SEQUENCE {
            //   modulus            INTEGER,    -- n
            //   publicExponent     INTEGER  }  -- e
            const [n, e] = derArrayFromSEQUENCE(DER_DECODE(extractBytesFromBITSTRING(spki)));
            return {
                kty: 'RSA',
                raw: der.raw,
                n: extractNonNegativeIntegerFromInteger(n),
                e: extractNonNegativeIntegerFromInteger(e),
            };
        }
        // このOID(id-ecPublicKey) は EC 公開鍵を識別する (RFC5480)
        case '1.2.840.10045.2.1': {
            // namedCurve 以外はPKIX では使われないのでスルー (RFC5480)
            // EcpkParameters ::= CHOICE {
            //  namedCurve    OBJECT IDENTIFIER,
            //  implicitCurve  NULL,
            //  specifiedCurve SpecifiedECDomain }
            if (param.class !== 'Universal' || param.tag !== TAG_OBJECTIDENTIFIER) {
                throw EvalError('EC公開鍵のパラメータは OID 指定のみ実装する');
            }
            // 圧縮されていない前提で考えている。
            // 圧縮されていない場合 spki には  0x04 || x || y で公開鍵がエンコードされている.
            const xy = extractBytesFromBITSTRING(spki);
            const x = xy.slice(1, (xy.length - 1) / 2 + 1);
            const y = xy.slice((xy.length - 1) / 2 + 1);
            switch (convertDotNotationFromOID(param)) {
                // secp256r1 つまり P-256 カーブを意味する
                case '1.2.840.10045.3.1.7':
                    return { kty: 'EC', raw: der.raw, crv: 'P-256', x, y };
                // secp384r1 つまり P-384 カーブを意味する
                case '1.3.132.0.34':
                    return { kty: 'EC', raw: der.raw, crv: 'P-384', x, y };
                default:
                    throw EvalError('SPKI parser for ec unimplmented');
            }
        }
        default:
            throw EvalError('SPKI parser Unimplemented!');
    }
}
const TAG_INTEGER = 2;
const TAG_BITSTRING = 3;
const TAG_NULL = 5;
const TAG_OBJECTIDENTIFIER = 6;
const TAG_SEQUENCE = 16;
/**
 * Primitive な DER で表現された Integer からバイナリ表現の非負整数を取り出す。
 * DER encoding では整数は符号付きなので非負整数は負の数と間違われないために先頭に 0x00 がついている。
 * 非負整数のみを扱うと分かっていれば別に先頭のオクテットはいらないので消して取り出す。
 */
function extractNonNegativeIntegerFromInteger(der) {
    if (der.class !== 'Universal' || der.pc !== 'Primitive' || der.tag !== TAG_INTEGER) {
        throw EvalError('INTEGER ではない DER format を扱おうとしている');
    }
    if (der.value[0] === 0x00) {
        return der.value.slice(1);
    }
    return der.value;
}
/**
 * Primitive な DER で表現された BITString からバイナリを取り出す
 */
function extractBytesFromBITSTRING(der) {
    if (der.class !== 'Universal' || der.pc !== 'Primitive' || der.tag !== TAG_BITSTRING) {
        throw EvalError('BITSTRING ではない DER format を扱おうとしている');
    }
    const v = der.value;
    // 先頭のオクテットはbit-length を８の倍数にするためにケツに追加した 0-padding の数を表現する
    if (v[0] === 0x00)
        return v.slice(1);
    // 先頭のオクテットが０でないときは、その数だけ padding 処理を行う
    const contentWithPadEnd = v.slice(1).reduce((sum, i) => sum + i.toString(2).padStart(8, '0'), '');
    const content = contentWithPadEnd.slice(0, contentWithPadEnd.length - v[0]);
    const contentWithPadStart = '0'.repeat(v[0]) + content;
    const ans = new Uint8Array(contentWithPadStart.length / 8);
    for (let i = 0; i < ans.length; i++) {
        ans[i] = parseInt(contentWithPadStart.substr(i * 8, 8), 2);
    }
    return ans;
}
/**
 * OID の DER 表現から Object Identifier のドット表記に変換する
 */
function convertDotNotationFromOID(der) {
    if (der.class !== 'Universal' || der.pc !== 'Primitive' || der.tag !== TAG_OBJECTIDENTIFIER) {
        throw EvalError('OID ではない DER format を扱おうとしている');
    }
    const v = der.value;
    const ans = [];
    // the first octet has 40 * value1 + value2
    ans.push(Math.floor(v[0] / 40));
    ans.push(v[0] % 40);
    let i = 1;
    while (i < v.length) {
        if (v[i] < 0x80) {
            ans.push(v[i]);
            i++;
            continue;
        }
        let tmp = 0;
        do {
            tmp = tmp * 128 + (v[i] - 0x80) * 128;
            i++;
        } while (v[i] > 0x80);
        tmp += v[i];
        ans.push(tmp);
        i++;
    }
    return ans.join('.');
}
/**
 * Constructed な DER で表現された SEQUENCE を JSのオブジェクトである Array<DER> に変換する
 */
function derArrayFromSEQUENCE(der) {
    if (der.class !== 'Universal' || der.pc !== 'Constructed' || der.tag !== TAG_SEQUENCE) {
        throw EvalError('SEQUENCE ではない DER format を扱おうとしている');
    }
    const v = der.value;
    const ans = [];
    let start = 0;
    while (start < v.length) {
        const c = DER_DECODE(v.slice(start));
        ans.push(c);
        start += c.entireLen;
    }
    return ans;
}
/**
 * バイナリエンコードされている DER を何の値を表現するかまでパースする。
 */
function DER_DECODE(ber) {
    const { tag, typeFieldLen } = parseTagNum(ber);
    const { len, lengthFieldLen } = parseLength(ber.slice(typeFieldLen));
    const value = ber.slice(typeFieldLen + lengthFieldLen, typeFieldLen + lengthFieldLen + len);
    return {
        class: parseClass(ber),
        pc: parsePC(ber),
        tag,
        len,
        entireLen: typeFieldLen + lengthFieldLen + len,
        value,
        raw: ber.slice(0, typeFieldLen + lengthFieldLen + len),
    };
}
/**
 * TypeField の最初の２ビットがクラスを表現している
 */
function parseClass(typeField) {
    const cls = (typeField[0] & 0xc0) >> 6;
    switch (cls) {
        case 0:
            return 'Universal';
        case 1:
            return 'Application';
        case 2:
            return 'ContentSpecific';
        case 3:
            return 'Private';
        default:
            throw EvalError('クラスは 00 ~ 11 の範囲のみ');
    }
}
/**
 * TypeField の3ビット目が基本型か構造型かを表現している
 */
function parsePC(typeField) {
    const ps = (typeField[0] & 0x20) >> 5;
    switch (ps) {
        case 0:
            return 'Primitive';
        case 1:
            return 'Constructed';
        default:
            throw EvalError('P/C は 0 か 1 のいずれか');
    }
}
/**
 * TypeField の4ビット目以降が Tag番号を表現している。
 * tag number < 31 なら TypeField は１オクテットだが、
 * 超えるようならいい感じに後ろのオクテットも使って表現する。
 * そのため Tag 番号をパースすることで初めて TypeField のオクテット長が決まる。
 */
function parseTagNum(typeField) {
    // Type Field の下位５ビットが tag を表現する.
    let tag = typeField[0] & 0x1f;
    // 全てが１でないなら、それは Tag number を表現している。
    // 全て１の時は後続が tag を表現している。
    if (tag < 0x1f)
        return { tag, typeFieldLen: 1 };
    tag = 0;
    let i = 0;
    do {
        i++;
        // 後続オクテットの下位7bit が tag number を表現
        // 上位１bit が一である限り後続も tag number を表現しているので、
        // それらを連結したものが tag number
        const t = typeField[i] & 0x7f;
        tag = (tag << 7) + t;
    } while ((typeField[i] & 0x80) >> 7 !== 0);
    return { tag, typeFieldLen: 1 + i };
}
/**
 * LengthField を解釈して Value のオクテット長を求める。
 * Value の長さが 127 以下なら LengthField は 1 オクテットで表現されるが、
 * 超えるようならいい感じに後ろのオクテットも使って表現する。
 * そのため Length をパースすることで初めて Length Field のオクテット長が決まる
 */
function parseLength(lengthField) {
    if (lengthField[0] < 0x80) {
        return { len: lengthField[0] & 0x7f, lengthFieldLen: 1 };
    }
    // Length Field の先頭１ビットが１の時は、長さが 128 を超えているということ
    const additionalLengthFieldLen = lengthField[0] & 0x7f;
    let len = 0;
    for (let i = 0; i < additionalLengthFieldLen; i++) {
        len = (len << 8) + lengthField[1 + i];
    }
    return { len, lengthFieldLen: 1 + additionalLengthFieldLen };
}
/**
 * バイナリに文字列を BASE64 デコードする
 */
function BASE64_DECODE(STRING) {
    const b_str = window.atob(STRING);
    // バイナリ文字列を Uint8Array に変換する
    const b = new Uint8Array(b_str.length);
    for (let i = 0; i < b_str.length; i++) {
        b[i] = b_str.charCodeAt(i);
    }
    return b;
}
// --------------------END X.509 DER parser --------------------

// --------------------BEGIN JWK definition --------------------
/**
 * 引数が JWK オブジェクトであるかどうか確認する。
 * kty を指定するとその鍵タイプの JWK 形式を満たすか確認する。
 * asym を指定すると非対称暗号鍵のうち指定した鍵（公開鍵か秘密鍵）かであるかも確認する。
 */
function isJWK(arg, kty, asym) {
    // kty を指定しないときは、最低限 JWK が持つべき情報を持っているか確認する
    if (kty == null)
        return isCommonJWKParams(arg);
    if (isJWAKty(kty))
        return isJWAJWK(arg, kty, asym);
    return false;
}
function equalsJWK(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    if (isJWAKty(l.kty))
        return equalsJWAJWK(l, r);
    return false;
}
/**
 * 秘密鍵から公開鍵情報を取り出す。
 */
function exportPublicKey(priv) {
    if (isJWAKty(priv.kty))
        return exportJWAPublicKey(priv);
    throw new EvalError(`${priv.kty} の公開鍵を抽出できなかった`);
}
/**
 * 引数が JWK Set かどうか判定する.
 * keys パラメータが存在して、その値が JWK の配列なら OK
 */
const isJWKSet = (arg) => isObject(arg) && Array.isArray(arg.keys) && arg.keys.every((k) => isJWK(k));
/**
 * 引数 alg に応じた kty の値を返す関数
 */
const ktyFromAlg = (alg) => {
    if (isJWASigAlg(alg) || isJWAMACAlg(alg))
        return ktyFromJWAJWSAlg(alg);
    throw new TypeError(`${alg} に対応する kty がわからなかった`);
};
/**
 * RFC7515(JWS)#6 Key Identification
 *
 */
function identifyJWK(h, set) {
    // JWKSet が JOSE Header 外の情報で取得できていれば、そこから必要な鍵を選ぶ
    if (set) {
        for (const key of set.keys) {
            // RFC7515#4.5 kid Parameter
            // JWK Set のなかで kid が使われつとき、異なる鍵に別々の "kid" 値が使われるべき (SHOULD)
            // (異なる鍵で同じ "kid" 値が使われる例: 異なる "kty" で、それらを使うアプリで同等の代替鍵としてみなされる場合)
            if (isAlg(h.alg) && key.kty === ktyFromAlg(h.alg) && key.kid === h.kid) {
                return key;
            }
        }
    }
    // JOSE Header のパラメータを読み取るのは未実装
    throw new EvalError(` JOSEheader(${h}) と JWKSet(${set}) から鍵を識別できなかった`);
}
/**
 * 型で表現しきれない JWK の条件を満たすか確認する。
 * options に渡された条件を jwk が満たすか確認する
 * options.x5c を渡すことで、 jwk.x5c があればそれを検証する。
 * options.x5c.selfSigned = true にすると、x5t が自己署名証明書だけを持つか確認し、
 * 署名が正しいか確認する。また jwk パラメータと同じ内容が書かれているか確認する。
 */
async function validJWK(jwk, options) {
    if (!validCommonJWKParams(jwk))
        return false;
    if (options == null)
        return true;
    if (options.use != null) {
        if (options.use !== jwk.use)
            return false;
    }
    if (options.x5c != null) {
        const err = await validJWKx5c(jwk, options.x5c?.selfSigned);
        if (err != null) {
            throw EvalError(err);
        }
    }
    return true;
}
async function validJWKx5c(jwk, selfSigned = false) {
    if (jwk.x5c == null)
        return 'JWK.x5c parameter not found';
    if (jwk.x5c.length === 1 && !selfSigned)
        return 'JWK.x5c is self-signed certificate';
    // The key in the first certificate MUST match the public key represented by other members of the JWK. (RFC7517)
    // jwk.x5c[0] が表現する公開鍵はその jwk が表現する値と同じでなければならない
    const crt1 = parseX509BASE64EncodedDER(jwk.x5c[0]);
    switch (jwk.kty) {
        case 'RSA':
            if (crt1.tbs.spki.kty === 'RSA' &&
                isX509SPKI(crt1.tbs.spki, 'RSA') &&
                jwk.n === BASE64URL(crt1.tbs.spki.n) &&
                jwk.e === BASE64URL(crt1.tbs.spki.e)) {
                break;
            }
            return 'JWK.x5c[0] does not match with JWK parameteres';
        case 'EC':
            if (crt1.tbs.spki.kty === 'EC' &&
                isX509SPKI(crt1.tbs.spki, 'EC') &&
                jwk.x === BASE64URL(crt1.tbs.spki.x) &&
                jwk.y === BASE64URL(crt1.tbs.spki.y)) {
                break;
            }
            return 'JWK.x5c[0] does not match with JWK parameteres';
        case 'oct':
            return 'JWK.x5c does not support symmetric key representation';
    }
    if (jwk.x5c.length > 1)
        throw EvalError('証明書チェーンが１の長さで、かつ自己署名の場合のみ実装している');
    const crt = parseX509BASE64EncodedDER(jwk.x5c[0]);
    if (!(await validateSelfSignedCert(crt))) {
        return 'JWK.x5c Signature Verification Error';
    }
}
// --------------------END JWK definition --------------------

// --------------------BEGIN JWS MAC algorithms --------------------
/**
 * 引数が JWS の MAC アルゴリズムか確認する
 */
const isJWSMACAlg = (arg) => isJWAMACAlg(arg);
/**
 * MAC アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newMacOperator(alg) {
    if (isJWAMACAlg(alg))
        return newJWAMACOperator(alg);
    throw TypeError(`MacOperator<${alg}> は実装されていない`);
}
// --------------------END JWS MAC algorithms --------------------

// --------------------BEGIN JWS Digital Signature algorithms --------------------
/**
 * 引数が JWS の署名アルゴリズム識別子か確認する
 */
const isJWSSigAlg = (arg) => isJWASigAlg(arg);
/**
 * 署名アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newSigOperator(alg) {
    if (isJWASigAlg(alg))
        return newJWASigOperator(alg);
    throw new TypeError(`SigOperator<${alg}> は実装されていない`);
}
function ktyFromJWSSigAlg(alg) {
    if (isJWASigAlg(alg))
        return ktyFromJWAJWSAlg(alg);
    throw new TypeError(`${alg} は JWSSigAlg ではない`);
}
// --------------------END JWS Digital Signature algorithms --------------------

const isJWSAlg = (arg) => isJWSSigAlg(arg) || isJWSMACAlg(arg) || (typeof arg === 'string' && arg === 'none');

// --------------------BEGIN JWS Header definition --------------------
/**
 * JWS では JOSE Header は JWS Protected Header と JWS Unprotected Header の union で表現されるが、
 * 内部構造としてヘッダーパラメータが Protected かどうかという情報を保持し続けるためにクラスで定義している。
 * p と u のいずれか一方は存在することが必要で、どちらかには alg パラメータが含まれている
 */
class JWSHeader {
    constructor(p, u) {
        const h = { ...u, ...p };
        if (!isJWSJOSEHeader(h))
            throw new TypeError('JOSE Header for JWS に必要なパラメータが不足している');
        this.h = h;
        this.p = p;
        this.u = u;
    }
    /**
     * JWS Protected Header と JWS Unprotected Header の Union を返す
     */
    get JOSEHeader() {
        return this.h;
    }
    /**
     * JWS Protected Header があれば返す。
     */
    get Protected() {
        return this.p;
    }
    /**
     * JWS Unprotected Header があれば返す。
     */
    get Unprotected() {
        return this.u;
    }
}
const isJWSProtectedHeader = (arg) => isPartialJWSJOSEHeader(arg);
const isJWSUnprotectedHeader = (arg) => isPartialJWSJOSEHeader(arg);
const jwsJOSEHeaderNameList = [
    'alg',
    'jku',
    'jwk',
    'kid',
    'x5u',
    'x5c',
    'x5t',
    'x5t#S256',
    'typ',
    'cty',
    'crit',
];
/**
 * ２つの JWSJOSEHEader が同じか判定する
 */
function equalsJWSJOSEHeader(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    for (const n of jwsJOSEHeaderNameList) {
        const ln = l[n];
        const rn = r[n];
        if (ln == null && rn == null)
            continue;
        if (ln == null || rn == null)
            return false;
        switch (n) {
            case 'jwk': {
                const ll = ln;
                const rr = rn;
                if (equalsJWK(ll, rr))
                    continue;
                return false;
            }
            case 'x5t':
            case 'crit': {
                const ll = ln;
                const rr = rn;
                if (new Set(ll).size === new Set(rr).size && ll.every((l) => rr.includes(l)))
                    continue;
                return false;
            }
            default: {
                const ll = ln;
                const rr = rn;
                if (ll === rr)
                    continue;
                return false;
            }
        }
    }
    return true;
}
/**
 * 引数が JWSJOSEHeader か確認する。
 * JWS で定義されている JWSJOSEHeader パラメータをもち、 alg を持っているか確認する。
 */
const isJWSJOSEHeader = (arg) => isPartialJWSJOSEHeader(arg) && arg.alg != null;
/**
 * 引数が Partial<JWSJOSEHeader> か確認する。
 * isJWSJOSEHeader は alg が値を持っているか確認するが、これでは undefined でも良いとしている。
 */
const isPartialJWSJOSEHeader = (arg) => isObject(arg) &&
    jwsJOSEHeaderNameList.every((n) => arg[n] == null ||
        (n === 'alg'
            ? isJWSAlg(arg[n])
            : n === 'jwk'
                ? isJWK(arg[n])
                : n === 'x5c' || n === 'crit'
                    ? Array.isArray(arg[n]) && arg[n].every((m) => typeof m === 'string')
                    : typeof arg[n] === 'string'));
// --------------------END JWS Header definition --------------------

// --------------------BEGIN JWS Serialization definition --------------------
/**
 * Serialization された JWS のフォーマットが何か判定する
 */
function serializationType(data) {
    if (typeof data == 'string') {
        return 'compact';
    }
    if (typeof data == 'object' && data != null) {
        if ('signatures' in data)
            return 'json';
        return 'json-flat';
    }
    throw TypeError(`${data} は JWSSerialization ではない`);
}
/**
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * に JWS をシリアライズする。
 */
function serializeCompact(h, m, s) {
    let ans = BASE64URL(UTF8(JSON.stringify(h))) + '.' + BASE64URL(m);
    if (s != null)
        ans += '.' + BASE64URL(s);
    return ans;
}
/**
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * を JWS にデシリアライズする。
 */
function deserializeCompact(compact) {
    const c = compact.split('.');
    if (c.length !== 3) {
        throw 'JWS Compact Serialization の形式ではない';
    }
    const [header, payload, signature] = c;
    if (header === '') {
        throw 'JWS Compact Serialization では Protected Header が必須';
    }
    return {
        h: JSON.parse(UTF8_DECODE(BASE64URL_DECODE(header))),
        m: BASE64URL_DECODE(payload),
        s: BASE64URL_DECODE(signature),
    };
}
function isJWSJSONSerialization(arg) {
    return (isObject(arg) &&
        typeof arg.payload === 'string' &&
        Array.isArray(arg.signatures) &&
        arg.signatures.every((s) => isObject(s) &&
            typeof s.signature === 'string' &&
            (s.header == null || isJWSUnprotectedHeader(s.header)) &&
            (s.protected == null || typeof s.protected === 'string')));
}
function serializeJSON(m, hs) {
    const hsList = Array.isArray(hs) ? hs : [hs];
    return {
        payload: BASE64URL(m),
        signatures: hsList.map((hs) => {
            if (hs.s === undefined) {
                throw '署名を終えていない';
            }
            return {
                signature: BASE64URL(hs.s),
                header: hs.h.Unprotected,
                protected: hs.h.Protected !== undefined
                    ? BASE64URL(UTF8(JSON.stringify(hs.h.Protected)))
                    : undefined,
            };
        }),
    };
}
function deserializeJSON(json) {
    return {
        m: BASE64URL_DECODE(json.payload),
        hs: json.signatures.map((sig) => ({
            s: BASE64URL_DECODE(sig.signature),
            h: new JWSHeader(sig.protected !== undefined
                ? JSON.parse(UTF8_DECODE(BASE64URL_DECODE(sig.protected)))
                : undefined, sig.header),
        })),
    };
}
function equalsJWSJSONSerialization(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    for (const n of ['payload', 'signatures']) {
        const ln = l[n];
        const rn = r[n];
        if (ln == null && rn == null)
            continue;
        if (ln == null || rn == null)
            return false;
        if (n === 'payload') {
            if (ln === rn)
                continue;
            return false;
        }
        else if (n === 'signatures') {
            const ll = ln;
            const rr = rn;
            if (ll.every((l) => rr.some((r) => equalsSignatureInJWSJSONSerialization(l, r))) &&
                rr.every((r) => ll.some((l) => equalsSignatureInJWSJSONSerialization(l, r))))
                continue;
            return false;
        }
    }
    return true;
}
function equalsSignatureInJWSJSONSerialization(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    for (const n of ['signature', 'header', 'protected']) {
        const ln = l[n];
        const rn = r[n];
        if (ln == null && rn == null)
            continue;
        if (ln == null || rn == null)
            return false;
        switch (n) {
            case 'header': {
                const ll = ln;
                const rr = rn;
                if (equalsJWSJOSEHeader(ll, rr))
                    continue;
                return false;
            }
            case 'protected':
            case 'signature': {
                if (ln === rn)
                    continue;
                return false;
            }
        }
    }
    return true;
}
function equalsJWSFlattenedJSONSerialization(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    if (l.payload !== r.payload)
        return false;
    return equalsSignatureInJWSJSONSerialization(l, r);
}
const isJWSFlattenedJSONSerialization = (arg) => isObject(arg) &&
    typeof arg.payload === 'string' &&
    (arg.protected == null || typeof arg.protected === 'string') &&
    typeof arg.signature === 'string' &&
    (arg.header == null || isJWSUnprotectedHeader(arg.header));
// --------------------END JWS Serialization definition --------------------

/**
 * JWS はデジタル署名もしくはメッセージ認証コードで保護されたコンテンツを表現する JSON ベースのデータ構造である。
 */
class JWS {
    constructor(m, hs) {
        this.m = m;
        this.hs = hs;
    }
    /**
     * RFC7515#5.1 Message Signature or MAC Computation
     *
     */
    static async produce(keys, 
    /**
     * JWS Payload として使用するコンテンツ。
     */
    m, 
    /**
     * JOSE ヘッダー。複数署名を行う場合は配列で表現。
     */
    h) {
        const headerList = Array.isArray(h)
            ? h.map((h) => new JWSHeader(h.p, h.u))
            : [new JWSHeader(h.p, h.u)];
        // ヘッダーごとにコンテンツに対して署名や MAC 計算を行う。
        // 計算の実体は sign で実装。
        const hsList = await Promise.all(headerList.map(async (h) => ({ h, s: await sign(keys, m, h) })));
        if (hsList.length === 1)
            return new JWS(m, hsList[0]);
        return new JWS(m, hsList);
    }
    async validate(keys, isAllValidation = true) {
        const hsList = Array.isArray(this.hs) ? this.hs : [this.hs];
        const verifiedList = await Promise.all(hsList.map(async (hs) => await verify(keys, this.m, hs)));
        return verifiedList.reduce((prev, now) => (isAllValidation ? prev && now : prev || now));
    }
    static deserialize(data) {
        switch (serializationType(data)) {
            case 'compact': {
                const { h, m, s } = deserializeCompact(data);
                return new JWS(m, { h: new JWSHeader(h), s });
            }
            case 'json': {
                const { m, hs } = deserializeJSON(data);
                if (hs.length === 1) {
                    return new JWS(m, hs[0]);
                }
                return new JWS(m, hs);
            }
            case 'json-flat': {
                const d = data;
                const { m, hs } = deserializeJSON({ payload: d.payload, signatures: [d] });
                return new JWS(m, hs[0]);
            }
        }
    }
    serialize(s) {
        switch (s) {
            case 'compact':
                if (Array.isArray(this.hs)) {
                    throw 'JWS Compact Serialization は複数署名を表現できない';
                }
                if (this.hs.h.Protected == null) {
                    // つまり this.hs.h.u != null
                    throw 'JWS Compact Serialization は JWS Unprotected Header を表現できない';
                }
                if (this.hs.s == null) {
                    throw '署名を終えていない';
                }
                return serializeCompact(this.hs.h.Protected, this.m, this.hs.s);
            case 'json':
                return serializeJSON(this.m, this.hs);
            case 'json-flat': {
                const json = serializeJSON(this.m, this.hs);
                if (json.signatures.length > 1) {
                    throw 'Flattened JWS JSON Serialization は複数署名を表現できない';
                }
                return {
                    payload: json.payload,
                    signature: json.signatures[0].signature,
                    header: json.signatures[0].header,
                    protected: json.signatures[0].protected,
                };
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
async function sign(keys, m, h) {
    const input = jwsinput(m, h.Protected);
    const jh = h.JOSEHeader;
    const alg = jh.alg;
    if (jh.alg === 'none') {
        // Unsecured JWS の場合は、署名値がない。
        return new Uint8Array();
    }
    else if (isJWSSigAlg(alg)) {
        // JOSE Header の alg がデジタル署名の場合
        const key = identifyJWK(jh, keys);
        // key が秘密鍵かどうか、型ガードを行う
        if (!isJWK(key, ktyFromJWSSigAlg(alg), 'Priv'))
            throw new TypeError('公開鍵で署名しようとしている');
        return newSigOperator(alg).sign(alg, key, input);
    }
    else if (isJWSMACAlg(alg)) {
        // JOSE Header の alg が MAC の場合
        const key = identifyJWK(jh, keys);
        return newMacOperator(alg).mac(alg, key, input);
    }
    throw new EvalError(`sign(alg: ${alg}) is unimplemented`);
}
async function verify(keys, m, hs) {
    const jh = hs.h.JOSEHeader;
    const alg = jh.alg;
    if (alg === 'none')
        return true;
    if (hs.s === undefined)
        return false;
    const input = jwsinput(m, hs.h.Protected);
    if (isJWSSigAlg(alg)) {
        const key = identifyJWK(jh, keys);
        if (!isJWK(key, ktyFromJWSSigAlg(alg), 'Pub'))
            throw new TypeError('秘密鍵で検証しようとしている');
        return newSigOperator(alg).verify(alg, key, input, hs.s);
    }
    else if (isJWSMACAlg(alg)) {
        const key = identifyJWK(jh, keys);
        return newMacOperator(alg).verify(alg, key, input, hs.s);
    }
    throw new EvalError(`verify(alg: $alg) is unimplemented`);
}
/**
 * RFC7515#2 JWS Signing Input はデジタル署名や MAC の計算に対する入力。
 * この値は、ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))
 */
const jwsinput = (m, p) => ASCII((p !== undefined ? BASE64URL(UTF8(JSON.stringify(p))) : '') + '.' + BASE64URL(m));

const paths = [
    '4_1.rsa_v15_signature.json',
    '4_2.rsa-pss_signature.json',
    '4_3.ecdsa_signature.json',
    '4_4.hmac-sha2_integrity_protection.json',
    // "4_5.signature_with_detached_content.json",
    '4_6.protecting_specific_header_fields.json',
    '4_7.protecting_content_only.json',
    '4_8.multiple_signatures.json',
];
const baseURL = 'https://raw.githubusercontent.com/ietf-jose/cookbook/master/jws/';
async function fetchData(path) {
    const resp = await fetch(baseURL + path);
    const data = await resp.json();
    if (isData(data))
        return data;
    throw new EvalError('テストデータの取得に失敗');
}
function isData(arg) {
    return (isObject(arg) &&
        typeof arg.title === 'string' &&
        (arg.reproducible == null || typeof arg.reproducible === 'boolean') &&
        isObject(arg.input) &&
        typeof arg.input.payload === 'string' &&
        (Array.isArray(arg.input.key)
            ? arg.input.key.every((k) => isJWK(k))
            : isJWK(arg.input.key)) &&
        (Array.isArray(arg.input.alg)
            ? arg.input.alg.every((a) => isAlg(a))
            : isAlg(arg.input.alg)) &&
        isObject(arg.signing) &&
        (Array.isArray(arg.signing)
            ? arg.signing.every((s) => isObject(s) &&
                (s.protected == null || isJWSProtectedHeader(s.protected)) &&
                (s.unprotected == null || isJWSUnprotectedHeader(s.unprotected)))
            : (arg.signing.protected == null || isJWSProtectedHeader(arg.signing.protected)) &&
                (arg.signing.unprotected == null || isJWSUnprotectedHeader(arg.signing.unprotected))) &&
        isObject(arg.output) &&
        (arg.output.compact == null || typeof arg.output.compact === 'string') &&
        isJWSJSONSerialization(arg.output.json) &&
        (arg.output.json_flat == null || isJWSFlattenedJSONSerialization(arg.output.json_flat)));
}

// --------------------BEGIN RFC7517 appendix.A test --------------------
async function test$5() {
    let allGreen = true;
    const title = 'RFC7517#A Example JSON Web Key Sets;';
    let log = 'TEST NAME: A.1.Example Public Keys: ';
    // JWK Set contains two public keys represented as JWKs
    if (!isJWKSet(a1)) {
        log += 'JWK Set と判定できていない\n';
        allGreen = false;
    }
    else {
        // one using an Elliptic Curve algorithm and a second one using an RSA algorithm.
        if (isJWK(a1.keys[0], 'EC', 'Pub') && isJWK(a1.keys[1], 'RSA', 'Pub')) {
            log += 'JWKSet([JWK<EC,Pub>, JWK<RSA,Pub>]) と判定できた (OK)\n';
        }
        else {
            log += 'JWK Set に含まれる公開鍵の種類の判定に失敗\n';
            allGreen = false;
        }
    }
    log += 'TEST NAME: A.2. Example Private Keys: ';
    if (!isJWKSet(a2)) {
        log += 'JWK Set と判定できていない\n';
        allGreen = false;
    }
    else {
        // one using an Elliptic Curve algorithm and a second one using an RSA algorithm.
        if (isJWK(a2.keys[0], 'EC', 'Priv') && isJWK(a2.keys[1], 'RSA', 'Priv')) {
            log += 'JWKSet([JWK<EC,Priv>, JWK<RSA,Priv>]) と判定できた (OK)\n';
        }
        else {
            log += 'JWK Set に含まれる秘密鍵の種類の判定に失敗\n';
            allGreen = false;
        }
    }
    log += 'TEST NAME: A.3. Example Symmetric Keys: ';
    if (!isJWKSet(a3)) {
        log += 'JWK Set と判定できていない\n';
        allGreen = false;
    }
    else {
        // JWK Set contains two symmetric keys represented as JWKs:
        if (isJWK(a3.keys[0], 'oct') && isJWK(a3.keys[1], 'oct')) {
            log += 'JWKSet([JWK<oct>, JWK<oct>]) と判定できた (OK)\n';
        }
        else {
            log += 'JWK Set に含まれる対称鍵の種類の判定に失敗\n';
            allGreen = false;
        }
    }
    return { title, log, allGreen };
}
const a1 = {
    keys: [
        {
            kty: 'EC',
            crv: 'P-256',
            x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
            y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
            use: 'enc',
            kid: '1',
        },
        {
            kty: 'RSA',
            n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            e: 'AQAB',
            alg: 'RS256',
            kid: '2011-04-29',
        },
    ],
};
const a2 = {
    keys: [
        {
            kty: 'EC',
            crv: 'P-256',
            x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
            y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
            d: '870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE',
            use: 'enc',
            kid: '1',
        },
        {
            kty: 'RSA',
            n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISnnD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            e: 'AQAB',
            d: 'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q',
            p: '83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs',
            q: '3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk',
            dp: 'G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0',
            dq: 's9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk',
            qi: 'GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU',
            alg: 'RS256',
            kid: '2011-04-29',
        },
    ],
};
const a3 = {
    keys: [
        { kty: 'oct', alg: 'A128KW', k: 'GawgguFyGrWKav7AX4VKUg' },
        {
            kty: 'oct',
            k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
            kid: 'HMAC key used in JWS spec Appendix A.1 example',
        },
    ],
};
// --------------------END RFC7517 appendix.A test --------------------

// --------------------BEGIN RFC7517 appendix.B test --------------------
async function test$4() {
    let allGreen = true;
    const title = 'RFC7517#B.Example Use of "x5c" Parameter;';
    let log = 'TEST NAME: Self Signed Certificate Verification: ';
    const cert = parseX509BASE64EncodedDER(b.x5c[0]);
    const isVerified = await validateSelfSignedCert(cert);
    if (isVerified) {
        log += 'X509証明書(RSA) OK ';
    }
    else {
        log += 'X509証明書(RSA) X ';
        allGreen = false;
    }
    const eccert = parseX509BASE64EncodedDER(amazon_root_ca_3.x5c[0]);
    const isECVerified = await validateSelfSignedCert(eccert);
    if (isECVerified) {
        log += 'X509証明書(EC) OK\n';
    }
    else {
        log += 'X509証明書(EC) X\n';
        allGreen = false;
    }
    log += 'TEST NAME: Validate JWK.x5c\n';
    if (isJWK(b, 'RSA', 'Pub')) {
        if (await validJWK(b, { x5c: { selfSigned: true } })) {
            log += 'JWK.x5c (RSA) の検証と整合性の確認に成功\n';
        }
        else {
            log += 'JWK.x5c (RSA) の検証に失敗\n';
            allGreen = false;
        }
    }
    else {
        log += 'JWK<RSA,Pub> のパースに失敗\n';
        allGreen = false;
    }
    if (isJWK(amazon_root_ca_3, 'EC', 'Pub')) {
        if (await validJWK(amazon_root_ca_3, { x5c: { selfSigned: true } })) {
            log += 'JWK.x5c (EC) の検証と整合性の確認に成功\n';
        }
        else {
            log += 'JWK.x5c (EC) の検証に失敗\n';
            allGreen = false;
        }
    }
    else {
        log += 'JWK<EC, Pub> のパースに失敗\n';
        allGreen = false;
    }
    log += "TEST NAME: Validate JWK.x5c of microsoft's JWKSet for oidc: ";
    const data = await (await fetch('https://login.microsoftonline.com/common/discovery/v2.0/keys')).json();
    if (!isJWKSet(data)) {
        log += 'JWKSet の取得に失敗\n';
        allGreen = false;
    }
    else {
        for (const key of data.keys) {
            if (isJWK(key, 'RSA', 'Pub')) {
                if (await validJWK(key, { x5c: { selfSigned: true } })) {
                    log += 'JWK.x5c の検証と整合性の確認に成功\n';
                }
                else {
                    log += 'JWK.x5c の検証に失敗\n';
                    allGreen = false;
                }
            }
            else {
                log += 'MSから取得する鍵は全て RSA 公開鍵のはず\n';
                allGreen = false;
            }
        }
    }
    return { title, log, allGreen };
}
const b = {
    kty: 'RSA',
    use: 'sig',
    kid: '1b94c',
    n: 'vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ',
    e: 'AQAB',
    x5c: [
        'MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==',
    ],
};
// ref: https://good.sca3a.amazontrust.com/ に基づいて JWK を生成した
const amazon_root_ca_3 = {
    kty: 'EC',
    crv: 'P-256',
    x: 'KZenxkF_wA2b6AEbVsbyUqW6LbIS6NIu1_rJxdiqbR8',
    y: 'c4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt4',
    x5c: [
        'MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKlui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6jQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSrttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkrBqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteMYyRIHN8wfdVoOw==',
    ],
};
// --------------------END RFC7517 appendix.B test --------------------

// --------------------BEGIN RFC7520 Section.3 for EC test --------------------
async function test$3() {
    const baseURL = 'https://raw.githubusercontent.com/ietf-jose/cookbook/master/jwk/';
    const urlList = [
        '3_1.ec_public_key.json',
        '3_2.ec_private_key.json',
        '3_3.rsa_public_key.json',
        '3_4.rsa_private_key.json',
        '3_5.symmetric_key_mac_computation.json',
        '3_6.symmetric_key_encryption.json',
    ];
    const fetchData = async (path) => await (await fetch(baseURL + path)).json();
    let allGreen = true;
    const title = 'RFC7520#3 check EC key;';
    let log = '';
    for (const path of urlList) {
        log += `TEST NAME: ${path}: `;
        const data = await fetchData(path);
        if (!path.includes('ec')) {
            if (isJWK(data, 'EC')) {
                log += 'EC鍵ではないはずが、EC鍵だと識別されている。\n';
                allGreen = false;
            }
            else {
                log += 'EC鍵ではないと判定できた(OK)\n';
            }
        }
        else if (path === '3_1.ec_public_key.json') {
            if (!isJWK(data, 'EC', 'Pub')) {
                log += 'EC公開鍵の判定に失敗。\n';
                allGreen = false;
            }
            else {
                log += 'EC公開鍵と判定できた(OK)\n';
            }
            continue;
        }
        else if (path === '3_2.ec_private_key.json') {
            if (!isJWK(data, 'EC', 'Priv')) {
                log += 'EC秘密鍵の判定に失敗。\n';
                allGreen = false;
            }
            else {
                log += 'EC秘密鍵と判定できた(OK)\n';
            }
        }
        else {
            log += '想定していないテストケース';
            allGreen = false;
        }
    }
    return { title, log, allGreen };
}
// --------------------END RFC7520 Section.3 for EC test --------------------

// --------------------BEGIN RFC7520 Section.3 for oct test --------------------
async function test$2() {
    const baseURL = 'https://raw.githubusercontent.com/ietf-jose/cookbook/master/jwk/';
    const urlList = [
        '3_1.ec_public_key.json',
        '3_2.ec_private_key.json',
        '3_3.rsa_public_key.json',
        '3_4.rsa_private_key.json',
        '3_5.symmetric_key_mac_computation.json',
        '3_6.symmetric_key_encryption.json',
    ];
    const fetchData = async (path) => await (await fetch(baseURL + path)).json();
    let allGreen = true;
    const title = 'RFC7520#3 check symmetry key;';
    let log = '';
    for (const path of urlList) {
        log += `TEST NAME: ${path}: `;
        const data = await fetchData(path);
        if (!path.includes('symmetric_key')) {
            if (isJWK(data, 'oct')) {
                log += 'oct鍵ではないはずが、oct鍵だと識別されている。\n';
                allGreen = false;
            }
            else {
                log += 'oct鍵ではないと判定できた(OK)\n';
            }
        }
        else if (path === '3_5.symmetric_key_mac_computation.json') {
            if (!isJWK(data, 'oct')) {
                console.log(data);
                log += 'oct鍵の判定に失敗。\n';
                allGreen = false;
            }
            else {
                log += 'oct鍵と判定できた(OK)\n';
            }
            continue;
        }
        else if (path === '3_6.symmetric_key_encryption.json') {
            if (!isJWK(data, 'oct')) {
                log += 'oct鍵の判定に失敗。\n';
                allGreen = false;
            }
            else {
                log += 'oct鍵と判定できた(OK)\n';
            }
        }
        else {
            log += '想定していないテストケース';
            allGreen = false;
        }
    }
    return { title, log, allGreen };
}
// --------------------END RFC7520 Section.3 for oct test --------------------

// --------------------BEGIN RFC7520 Section.3 for RSA test --------------------
async function test$1() {
    const baseURL = 'https://raw.githubusercontent.com/ietf-jose/cookbook/master/jwk/';
    const urlList = [
        '3_1.ec_public_key.json',
        '3_2.ec_private_key.json',
        '3_3.rsa_public_key.json',
        '3_4.rsa_private_key.json',
        '3_5.symmetric_key_mac_computation.json',
        '3_6.symmetric_key_encryption.json',
    ];
    const fetchData = async (path) => await (await fetch(baseURL + path)).json();
    let allGreen = true;
    const title = 'RFC7520#3 check RSA key;';
    let log = '';
    for (const path of urlList) {
        log += `TEST NAME: ${path}: `;
        const data = await fetchData(path);
        if (!path.includes('rsa')) {
            if (isJWK(data, 'RSA')) {
                log += 'RSA鍵ではないはずが、RSA鍵だと識別されている。\n';
                allGreen = false;
            }
            else {
                log += 'RSA鍵ではないと判定できた(OK)\n';
            }
        }
        else if (path === '3_3.rsa_public_key.json') {
            if (!isJWK(data, 'RSA', 'Pub')) {
                log += 'RSA公開鍵の判定に失敗。\n';
                allGreen = false;
            }
            else {
                log += 'RSA公開鍵と判定できた(OK)\n';
            }
            continue;
        }
        else if (path === '3_4.rsa_private_key.json') {
            if (!isJWK(data, 'RSA', 'Priv')) {
                log += 'RSA秘密鍵の判定に失敗。\n';
                allGreen = false;
            }
            else {
                log += 'RSA秘密鍵と判定できた(OK)\n';
            }
        }
        else {
            log += '想定していないテストケース';
            allGreen = false;
        }
    }
    return { title, log, allGreen };
}
// --------------------END RFC7520 Section.3 for RSA test --------------------

async function test(path) {
    const data = await fetchData(path);
    let allGreen = true;
    const title = 'RFC7520#4 TEST NAME: ' + data.title;
    let log = '';
    // 準備
    const payload = UTF8(data.input.payload);
    let header;
    if (Array.isArray(data.signing)) {
        header = data.signing.map((sig) => ({ p: sig.protected, u: sig.unprotected }));
    }
    else {
        header = { p: data.signing.protected, u: data.signing.unprotected };
    }
    const keys = {
        keys: Array.isArray(data.input.key) ? data.input.key : [data.input.key],
    };
    // 生成
    const jws = await JWS.produce(keys, payload, header);
    // 検証の準備
    const verifyKeys = {
        keys: keys.keys.map((k) => {
            if (isJWK(k, 'oct'))
                return k;
            if (isJWK(k, k.kty))
                return exportPublicKey(k);
            throw TypeError(`JWK ではない鍵が紛れ込んでいる $key`);
        }),
    };
    if (data.reproducible) {
        log += 'テストには再現性があるため、シリアライズした結果を比較する\n';
        const output = data.output;
        if (output.compact) {
            const compact = jws.serialize('compact');
            const same = output.compact === compact;
            allGreen &&= same;
            log += 'Compact: ' + (same ? '(OK) ' : 'X ');
        }
        if (output.json) {
            const json = jws.serialize('json');
            const same = equalsJWSJSONSerialization(output.json, json);
            allGreen &&= same;
            log += 'JSON: ' + (same ? '(OK) ' : 'X ');
        }
        if (output.json_flat) {
            const flat = jws.serialize('json-flat');
            const same = equalsJWSFlattenedJSONSerialization(output.json_flat, flat);
            allGreen &&= same;
            log += 'FlattenedJSON: ' + (same ? '(OK) ' : 'X ');
        }
        log += '\n';
    }
    else {
        log += 'テストには再現性がない (e.g. 署名アルゴリズムに乱数がからむ)\n';
    }
    log += 'JWS の検証する\n';
    const valid = await jws.validate(verifyKeys);
    allGreen &&= valid;
    log += 'Produce and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
    const output = data.output;
    if (output.compact) {
        const jws = JWS.deserialize(output.compact);
        const valid = await jws.validate(verifyKeys);
        allGreen &&= valid;
        log += 'Deserialize Compact and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
    }
    if (output.json) {
        const jws = JWS.deserialize(output.json);
        const valid = await jws.validate(verifyKeys);
        allGreen &&= valid;
        log += 'Deserialize JSON and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
    }
    if (output.json_flat) {
        const jws = JWS.deserialize(output.json_flat);
        const valid = await jws.validate(verifyKeys);
        allGreen &&= valid;
        log += 'Deserialize FlattendJSON and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
    }
    return { title, allGreen, log };
}

// --------------------BEGIN entry point --------------------
window.document.getElementById('jwk')?.addEventListener('click', test_jwk);
window.document.getElementById('jws')?.addEventListener('click', test_jws);
async function test_jwk() {
    const logs = await Promise.all([test$5, test$4, test$3, test$2, test$1].map(async (test) => await test()));
    logs.forEach(({ title, log, allGreen }) => {
        console.group(title, allGreen);
        console.log(log);
        console.groupEnd();
    });
}
async function test_jws() {
    const logs = await Promise.all(paths.map(async (path) => await test(path)));
    logs.forEach(({ title, log, allGreen }) => {
        console.group(title, allGreen);
        console.log(log);
        console.groupEnd();
    });
}
// --------------------END entry point --------------------
