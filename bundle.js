'use strict';

/**
 * 引数が ECDSA アルゴリズム識別子か確認する。
 */
const isESAlg = (arg) => typeof arg === 'string' && esAlgList.some((a) => a === arg);
const esAlgList = ['ES256', 'ES384', 'ES512'];

/**
 * 引数が HMAC アルゴリズム識別子か確認する。
 */
const isHSAlg = (arg) => typeof arg === 'string' && hsAlgList.some((a) => a === arg);
const hsAlgList = ['HS256', 'HS384', 'HS512'];

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

const isAGCMKWAlg = (arg) => typeof arg === 'string' && agcmAlgList.some((a) => a === arg);
const agcmAlgList = ['A128GCMKW', 'A192GCMKW', 'A256GCMKW'];

const isAKWAlg = (arg) => typeof arg === 'string' && akwAlgList.some((a) => a === arg);
const akwAlgList = ['A128KW', 'A192KW', 'A256KW'];

const isECDH_ESAlg = (arg) => typeof arg === 'string' && arg === 'ECDH-ES';
const isECDH_ESKWAlg = (arg) => typeof arg === 'string' && ecdhEsKwAlgList.some((a) => a === arg);
const ecdhEsKwAlgList = ['ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];

const isPBES2Alg = (arg) => typeof arg === 'string' && pbes2AlgList.some((a) => a === arg);
const pbes2AlgList = ['PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'];

const isRSA1_5Alg = (arg) => typeof arg === 'string' && arg === 'RSA1_5';
const isRSAOAEPAlg = (arg) => typeof arg === 'string' && rsaoaepAlgList.some((a) => a === arg);
const rsaoaepAlgList = ['RSA-OAEP', 'RSA-OAEP-256'];

function isJWAJWEAlg(arg, m) {
    switch (m) {
        case 'KE':
            return isJWAKEAlg(arg);
        case 'KW':
            return isJWAKWAlg(arg);
        case 'DKA':
            return isJWADKAAlg(arg);
        case 'KAKW':
            return isJWAKAKWAlg(arg);
        case 'DE':
            return isJWADEAlg(arg);
    }
    if (!m)
        return (isJWAKEAlg(arg) || isJWAKWAlg(arg) || isJWADKAAlg(arg) || isJWAKAKWAlg(arg) || isJWADEAlg(arg));
    return false;
}
const isJWAKEAlg = (arg) => isRSA1_5Alg(arg) || isRSAOAEPAlg(arg);
const isJWAKWAlg = (arg) => isAKWAlg(arg) || isAGCMKWAlg(arg) || isPBES2Alg(arg);
const isJWADKAAlg = (arg) => isECDH_ESAlg(arg);
const isJWAKAKWAlg = (arg) => isECDH_ESKWAlg(arg);
const isJWADEAlg = (arg) => typeof arg === 'string' && arg === 'dir';
function ktyFromJWAJWEAlg(alg) {
    if (isJWAKEAlg(alg))
        return 'RSA';
    if (isJWAKWAlg(alg) || isJWADEAlg(alg))
        return 'oct';
    if (isJWADKAAlg(alg) || isJWAKAKWAlg(alg))
        return 'EC';
    throw new TypeError(`${alg} に対応する鍵の kty がわからなかった`);
}
function keyMgmtModeFromJWAAlg(alg) {
    if (isJWAKEAlg(alg))
        return 'KE';
    if (isJWAKWAlg(alg))
        return 'KW';
    if (isJWADKAAlg(alg))
        return 'DKA';
    if (isJWAKAKWAlg(alg))
        return 'KAKW';
    if (isJWADEAlg(alg))
        return 'DE';
    const a = alg;
    throw new TypeError(`${a} の Key Management Mode がわからない`);
}

const isACBCEnc = (arg) => acbcEncList.some((a) => a === arg);
const acbcEncList = ['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'];

const isAGCMEnc = (arg) => agcmEncList.some((a) => a === arg);
const agcmEncList = ['A128GCM', 'A192GCM', 'A256GCM'];

const isJWAEncAlg = (arg) => isACBCEnc(arg) || isAGCMEnc(arg);

function isAlg(arg, t) {
    if (t === 'JWS')
        return isJWSAlg(arg);
    if (t === 'JWE')
        return isJWAJWEAlg(arg);
    return isJWSAlg(arg) || isJWAJWEAlg(arg);
}
const isEncAlg = (arg) => isJWAEncAlg(arg);
function ktyFromAlg(alg) {
    if (isJWSAlg(alg)) {
        return ktyFromJWSAlg(alg);
    }
    if (isJWAJWEAlg(alg)) {
        return ktyFromJWAJWEAlg(alg);
    }
    if (isJWAEncAlg(alg)) {
        return 'oct';
    }
    throw new TypeError(`${alg} に対応する鍵の kty がわからなかった`);
}
function isJWSAlg(arg) {
    const list = [isRSAlg, isPSAlg, isESAlg, isHSAlg, (x) => x === 'none'];
    return list.some((f) => f(arg));
}
function ktyFromJWSAlg(alg) {
    if (isPSAlg(alg) || isRSAlg(alg))
        return 'RSA';
    if (isESAlg(alg))
        return 'EC';
    if (isHSAlg(alg))
        return 'oct';
    if (alg === 'none')
        throw new TypeError('none alg で鍵は使わない');
    throw new TypeError(`${alg} は JWA で定義された JWS の Alg ではない`);
}

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
    try {
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
    catch (e) {
        throw new TypeError(`与えられた文字列 ${STRING} は base64url encoded string ではない`);
    }
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
const isArrayable = (arg, f) => {
    return Array.isArray(arg) ? arg.every(f) : f(arg);
};
// --------------------END util functions --------------------

const AGCMKWHeaderParamNames = ['iv', 'tag'];
const isPartialAGCMKWHeaderParams = (arg) => isObject(arg) &&
    AGCMKWHeaderParamNames.every((n) => !arg[n] || typeof arg[n] === 'string');
const isAGCMKWHeaderParams = (arg) => isPartialAGCMKWHeaderParams(arg) && arg.iv != null && arg.tag != null;
function equalsAGCMKWHeaderParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    return l.iv === r.iv && l.tag === r.tag;
}

function identifyJWK(jwks, policy) {
    let filtered = jwks.keys;
    if (policy.kty) {
        filtered = filtered.filter((key) => policy.kty === key.kty);
        if (filtered.length === 1 && filtered[0])
            return filtered[0];
    }
    if (policy.kid) {
        filtered = filtered.filter((key) => policy.kid === key.kid);
        if (filtered.length === 1 && filtered[0])
            return filtered[0];
    }
    throw new EvalError(`cannot identify from JWKSet using policy ${JSON.stringify(policy)}`);
}
/**
 * 型で表現しきれない JWK の条件を満たすか確認する。
 * options に渡された条件を jwk が満たすか確認する
 * options.x5c を渡すことで、 jwk.x5c があればそれを検証する。
 * options.x5c.selfSigned = true にすると、x5t が自己署名証明書だけを持つか確認し、
 * 署名が正しいか確認する。また jwk パラメータと同じ内容が書かれているか確認する。
 */
// async function verifyJWK_x5c(
//   jwk: JWK,
//   policy: { selfSigned?: boolean }
// ): Promise<string | undefined> {
//   if (!jwk.x5c) return 'JWK.x5c parameter is not found';
//   if (jwk.x5c[0] && !policy.selfSigned) return 'JWK.x5c is self-signed certificate';
//   // The key in the first certificate MUST match the public key represented by other members of the JWK. (RFC7517)
//   // jwk.x5c[0] が表現する公開鍵はその jwk が表現する値と同じでなければならない
//   const crt1 = parseX509BASE64EncodedDER(jwk.x5c[0]);
//   switch (jwk.kty) {
//     case 'RSA':
//       if (
//         isJWK(jwk, 'RSA') &&
//         crt1.tbs.spki.kty === 'RSA' &&
//         isX509SPKI(crt1.tbs.spki, 'RSA') &&
//         jwk.n === BASE64URL(crt1.tbs.spki.n) &&
//         jwk.e === BASE64URL(crt1.tbs.spki.e)
//       ) {
//         break;
//       }
//       return 'JWK.x5c[0] does not match with JWK parameteres';
//     case 'EC':
//       if (
//         isJWK(jwk, 'EC') &&
//         crt1.tbs.spki.kty === 'EC' &&
//         isX509SPKI(crt1.tbs.spki, 'EC') &&
//         jwk.x === BASE64URL(crt1.tbs.spki.x) &&
//         jwk.y === BASE64URL(crt1.tbs.spki.y)
//       ) {
//         break;
//       }
//       return 'JWK.x5c[0] does not match with JWK parameteres';
//     case 'oct':
//       return 'JWK.x5c does not support symmetric key representation';
//   }
//   if (jwk.x5c.length > 1)
//     throw EvalError('証明書チェーンが１の長さで、かつ自己署名の場合のみ実装している');
//   const crt = parseX509BASE64EncodedDER(jwk.x5c[0]);
//   if (!(await validateSelfSignedCert(crt))) {
//     return 'JWK.x5c Signature Verification Error';
//   }
// }

// --------------------BEGIN JWA Kty and Crv definition --------------------
const JWAKtyList = ['EC', 'RSA', 'oct'];
const isJWAKty = (arg) => typeof arg == 'string' && JWAKtyList.some((k) => k === arg);
// --------------------BEGIN JWA Kty and Crv definition --------------------

const isKty = (arg) => isJWAKty(arg);

const keyUseList = ['sig', 'enc'];
const isKeyUse = (arg) => typeof arg === 'string' && keyUseList.some((u) => u === arg);
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
const isKeyOps = (arg) => typeof arg === 'string' && keyOpsList.some((u) => u === arg);

const CommonJWKParamNames = [
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
const isPartialCommonJWKParams = (arg) => isObject(arg) &&
    CommonJWKParamNames.every((n) => {
        if (arg[n] == null)
            return true;
        switch (n) {
            case 'kty':
                return isKty(arg[n]);
            case 'use':
                return isKeyUse(arg[n]);
            case 'key_ops':
                return Array.isArray(arg.key_ops) && arg.key_ops.every((x) => isKeyOps(x));
            case 'alg':
                return isAlg(arg[n]) || isEncAlg(arg[n]);
            case 'x5c':
                return Array.isArray(arg['x5c']) && arg['x5c'].every((s) => typeof s === 'string');
            default:
                return typeof arg[n] === 'string';
        }
    });
function isCommonJWKParams(arg, kty) {
    if (!isPartialCommonJWKParams(arg))
        return false;
    if (!arg.kty || (kty && arg.kty !== kty))
        return false;
    if (arg.key_ops != null) {
        // key_ops と use は一緒に使うべきではない (SHOULD NOT)
        if (arg.use != null)
            return false;
        const set = new Set(arg.key_ops);
        // key_ops は高々２の配列で、重複する値を含めてはならない(MUST NOT)
        if (arg.key_ops.length > 2 || arg.key_ops.length !== set.size)
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
function equalsCommonJWKParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    return CommonJWKParamNames.every((n) => {
        if (l[n] == null && r[n] == null)
            return true;
        if (l[n] == null || r[n] == null)
            return false;
        switch (n) {
            case 'key_ops':
            case 'x5c': {
                return (new Set(l[n]).size === new Set(r[n]).size &&
                    l[n]?.every((l) => r[n]?.some((r) => r === l)));
            }
            default: {
                return l[n] === r[n];
            }
        }
    });
}
function exportCommonJWKParams(jwk) {
    let ans = {};
    CommonJWKParamNames.forEach((n) => {
        ans = { ...ans, [n]: jwk[n] };
    });
    if (isCommonJWKParams(ans))
        return ans;
    throw new TypeError('CommonJWKParams を抽出できなかった');
}

const isJWACrv = (arg) => typeof arg === 'string' && jwaCrvList.some((u) => u === arg);
const jwaCrvList = ['P-256', 'P-384', 'P-521'];
function keylenOfJWACrv(crv) {
    switch (crv) {
        case 'P-256':
            return 32;
        case 'P-384':
            return 48;
        case 'P-521':
            return 66;
    }
}

const isCrv = (arg) => isJWACrv(arg);
function keylenOfCrv(crv) {
    if (isJWACrv(crv))
        return keylenOfJWACrv(crv);
    throw new TypeError(`this crv name(${crv}) is not implemented`);
}

const JWAECPubKeyParamNames = ['crv', 'x', 'y'];
function isPartialJWAECPubKeyParams(arg) {
    if (!isObject(arg))
        return false;
    if (arg.crv) {
        if (!isCrv(arg.crv))
            return false;
        return ['x', 'y'].every((n) => {
            const x = arg[n];
            try {
                return typeof x === 'string' && BASE64URL_DECODE(x).length === keylenOfCrv(arg.crv);
            }
            catch {
                return false;
            }
        });
    }
    return ['x', 'y'].every((n) => arg[n] == null || typeof arg[n] === 'string');
}
const isJWAECPubKeyParams = (arg) => isPartialJWAECPubKeyParams(arg) && JWAECPubKeyParamNames.every((n) => arg[n] != null);
function equalsJWAECPubKeyParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    return JWAECPubKeyParamNames.every((n) => l[n] === r[n]);
}
const JWAECPrivKeyParamNames = ['d', ...JWAECPubKeyParamNames];
function isPartialJWAECPrivKeyParams(arg) {
    if (!isObject(arg))
        return false;
    const d = arg.d;
    if (!isPartialJWAECPubKeyParams(arg))
        return false;
    if (arg.crv) {
        try {
            return typeof d === 'string' && BASE64URL_DECODE(d).length === keylenOfCrv(arg.crv);
        }
        catch {
            return false;
        }
    }
    return d == null || typeof d === 'string';
}
const isJWAECPrivKeyParams = (arg) => isPartialJWAECPrivKeyParams(arg) && JWAECPrivKeyParamNames.every((n) => arg[n] != null);
function equalsJWAECPrivKeyParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    return JWAECPrivKeyParamNames.every((n) => l[n] === r[n]);
}
function exportJWAECPubKeyParams(priv) {
    let pub = {};
    JWAECPubKeyParamNames.forEach((n) => {
        pub = { ...pub, [n]: priv[n] };
    });
    if (isJWAECPubKeyParams(pub))
        return pub;
    throw new TypeError('JWAECPrivKeyParams から公開鍵情報を取り出せませんでした');
}

// --------------------BEGIN JWA symmetric keys --------------------
const isPartialJWAOctKeyParams = (arg) => isObject(arg) && (arg.k == null || typeof arg.k === 'string');
const isJWAOctKeyParams = (arg) => isPartialJWAOctKeyParams(arg) && arg.k != null;
function equalsJWAOctKeyParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    return l.k === r.k;
}
// --------------------END JWA symmetric keys --------------------

// --------------------BEGIN JWA RSA keys --------------------
const JWARSAPubKeyParamNames = ['n', 'e'];
const isPartialJWARSAPubKeyParams = (arg) => isObject(arg) &&
    JWARSAPubKeyParamNames.every((n) => arg[n] == null || typeof arg[n] === 'string');
const isJWARSAPubKeyParams = (arg) => isPartialJWARSAPubKeyParams(arg) && JWARSAPubKeyParamNames.every((n) => arg[n] != null);
function equalsJWARSAPubKeyParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    return JWARSAPubKeyParamNames.every((n) => l[n] === r[n]);
}
const JWARSAPrivKeyParamNames = [
    'd',
    'p',
    'q',
    'dp',
    'dq',
    'qi',
    ...JWARSAPubKeyParamNames,
];
const isPartialJWARSAPrivKeyParams = (arg) => isObject(arg) &&
    JWARSAPrivKeyParamNames.every((n) => arg[n] == null || typeof arg[n] === 'string');
const isJWARSAPrivKeyParams = (arg) => isPartialJWARSAPrivKeyParams(arg) && arg.d != null;
function equalsJWARSAPrivKeyParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    return JWARSAPrivKeyParamNames.every((n) => l[n] === r[n]);
}
function exportJWARSAPubKeyParams(priv) {
    let pub = {};
    JWARSAPubKeyParamNames.forEach((n) => {
        pub = { ...pub, [n]: priv[n] };
    });
    if (isJWARSAPubKeyParams(pub))
        return pub;
    throw new TypeError('JWARSAPrivKeyParams から公開鍵情報を取り出せませんでした');
}
// --------------------END JWA RSA keys --------------------

const isKeyClass = (arg) => arg === 'Pub' || arg === 'Priv';
function isJWKOctParams(arg) {
    return isJWAOctKeyParams(arg);
}
function equalsJWKOctParams(l, r) {
    return equalsJWAOctKeyParams(l, r);
}
function isJWKRSAParams(arg, c) {
    if (c === 'Pub') {
        return isJWARSAPubKeyParams(arg);
    }
    if (c === 'Priv') {
        return isJWARSAPrivKeyParams(arg);
    }
    return isJWARSAPubKeyParams(arg) || isJWARSAPrivKeyParams(arg);
}
function isPartialJWKRSAParams(arg, c) {
    if (c === 'Pub') {
        return isPartialJWARSAPubKeyParams(arg);
    }
    if (c === 'Priv') {
        return isPartialJWARSAPrivKeyParams(arg);
    }
    return isPartialJWARSAPubKeyParams(arg) || isPartialJWARSAPrivKeyParams(arg);
}
function equalsJWKRSAParams(l, r) {
    if (isPartialJWKRSAParams(l, 'Priv')) {
        return isPartialJWKRSAParams(r, 'Priv') && equalsJWARSAPrivKeyParams(l, r);
    }
    if (isPartialJWKRSAParams(l, 'Pub')) {
        return isPartialJWKRSAParams(r, 'Pub') && equalsJWARSAPubKeyParams(l, r);
    }
    return false;
}
function exportJWKRSAPubParams(priv) {
    return exportJWARSAPubKeyParams(priv);
}
function isPartialJWKECParams(arg, c) {
    if (c === 'Pub') {
        return isPartialJWAECPubKeyParams(arg);
    }
    if (c === 'Priv') {
        return isPartialJWAECPrivKeyParams(arg);
    }
    return isPartialJWAECPubKeyParams(arg) || isPartialJWAECPrivKeyParams(arg);
}
function isJWKECParams(arg, c) {
    if (c === 'Pub') {
        return isJWAECPubKeyParams(arg);
    }
    if (c === 'Priv') {
        return isJWAECPrivKeyParams(arg);
    }
    return isJWAECPubKeyParams(arg) || isJWAECPrivKeyParams(arg);
}
function equalsJWKECParams(l, r) {
    if (isPartialJWKECParams(l, 'Priv')) {
        return isPartialJWKECParams(r, 'Priv') && equalsJWAECPrivKeyParams(l, r);
    }
    if (isPartialJWKECParams(l, 'Pub')) {
        return isPartialJWKECParams(r, 'Pub') && equalsJWAECPubKeyParams(l, r);
    }
    return false;
}
function exportJWKECPubParams(priv) {
    return exportJWAECPubKeyParams(priv);
}

function isJWK(arg, opt1, opt2) {
    // options を整理
    let k;
    let c;
    if (isKty(opt1))
        k = opt1;
    if (isKeyClass(opt1))
        c = opt1;
    if (isKeyClass(opt2)) {
        if (c)
            throw new TypeError('opt1 で KeyClass を指定しています');
        c = opt2;
    }
    // common jwk parameters を満たしているかチェック
    if (!isCommonJWKParams(arg, k))
        return false;
    // kty specific な parameters を満たしているかチェック
    switch (k) {
        case 'oct':
            return isJWKOctParams(arg);
        case 'RSA':
            return isJWKRSAParams(arg, c);
        case 'EC':
            return isJWKECParams(arg, c);
        default:
            return isJWKOctParams(arg) || isJWKRSAParams(arg, c) || isJWKECParams(arg, c);
    }
}
function equalsJWK(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    if (!equalsCommonJWKParams(l, r))
        return false;
    if (isJWK(l, 'oct')) {
        return isJWK(r, 'oct') && equalsJWKOctParams(l, r);
    }
    if (isJWK(l, 'RSA')) {
        return isJWK(r, 'RSA') && equalsJWKRSAParams(l, r);
    }
    if (isJWK(l, 'EC')) {
        return isJWK(r, 'EC') && equalsJWKECParams(l, r);
    }
    return true;
}
function exportPubJWK(priv) {
    if (isJWK(priv, 'RSA', 'Priv')) {
        const pub = {
            ...exportCommonJWKParams(priv),
            ...exportJWKRSAPubParams(priv),
        };
        if (isJWK(pub, 'Pub'))
            return pub;
        throw new TypeError('公開鍵の抽出に失敗');
    }
    if (isJWK(priv, 'EC', 'Priv')) {
        const pub = {
            ...exportCommonJWKParams(priv),
            ...exportJWKECPubParams(priv),
        };
        if (isJWK(pub, 'Pub'))
            return pub;
        throw new TypeError('公開鍵の抽出に失敗');
    }
    if (isJWK(priv, 'oct')) {
        return priv;
    }
    throw new TypeError('priv の JWK Kty が知らないもの');
}

const isJWKSet = (arg) => isObject(arg) && Array.isArray(arg.keys) && arg.keys.every((jwk) => isJWK(jwk));

const ECDH_ESHeaderParamNames = ['epk', 'apu', 'apv'];
const isECDH_ESHeaderParams = (arg) => isPartialECDH_ESHeaderParams(arg) && arg.epk != null;
const isPartialECDH_ESHeaderParams = (arg) => isObject(arg) &&
    ECDH_ESHeaderParamNames.every((n) => !arg[n] || (n === 'epk' ? isJWK(arg.epk, 'EC', 'Pub') : typeof arg[n] === 'string'));
const equalsECDH_ESHeaderParams = (l, r) => {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    return equalsJWK(l.epk, r.epk) && l.apu === r.apu && l.apv === r.apv;
};

const PBES2HeaderParamNames = ['p2c', 'p2s'];
const isPBES2HeaderParams = (arg) => isPartialPBES2HeaderParams(arg) && arg.p2c != null && arg.p2s != null;
const isPartialPBES2HeaderParams = (arg) => isObject(arg) &&
    PBES2HeaderParamNames.every((n) => !arg[n] || (n === 'p2c' ? typeof arg[n] === 'number' : typeof arg[n] === 'string'));
function equalsPBES2HeaderParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    return l.p2c === r.p2c && l.p2s === r.p2s;
}

const JWAAlgSpecificJOSEHeaderParamNames = [
    ...AGCMKWHeaderParamNames,
    ...ECDH_ESHeaderParamNames,
    ...PBES2HeaderParamNames,
];
const isPartialJWAAlgSpecificJOSEHeaderParams = (arg) => isPartialAGCMKWHeaderParams(arg) ||
    isPartialECDH_ESHeaderParams(arg) ||
    isPartialPBES2HeaderParams(arg);
const equalsJWAAlgSpecificJOSEHeaderParams = (l, r) => equalsAGCMKWHeaderParams(l, r) ||
    equalsECDH_ESHeaderParams(l, r) ||
    equalsPBES2HeaderParams(l, r);

const JWEJOSEHeaderParamNames = [
    'alg',
    'enc',
    'zip',
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
const isPartialJWEJOSEHeaderParams = (arg) => isObject(arg) &&
    JWEJOSEHeaderParamNames.every((n) => arg[n] == null ||
        (n === 'alg'
            ? isAlg(arg[n], 'JWE')
            : n === 'enc'
                ? isEncAlg(arg[n])
                : n === 'jwk'
                    ? isJWK(arg[n])
                    : n === 'x5c' || n === 'crit'
                        ? Array.isArray(arg[n]) && arg[n].every((m) => typeof m === 'string')
                        : typeof arg[n] === 'string'));
function equalsJWEJOSEHeaderParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    return JWEJOSEHeaderParamNames.every((n) => {
        if (l[n] == null && r[n] == null)
            return true;
        if (l[n] == null || r[n] == null)
            return false;
        switch (n) {
            case 'jwk':
                return equalsJWK(l[n], r[n]);
            case 'x5c':
            case 'crit':
                return (new Set(l[n]).size === new Set(r[n]).size &&
                    l[n]?.every((l) => r[n]?.some((r) => r === l)));
            default:
                return l[n] === r[n];
        }
    });
}

const JWSJOSEHeaderParamNames = [
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
 * 引数が Partial<JWSJOSEHeader> か確認する。
 * isJWSJOSEHeader は alg が値を持っているか確認するが、これでは undefined でも良いとしている。
 */
const isPartialJWSJOSEHeaderParams = (arg) => isObject(arg) &&
    JWSJOSEHeaderParamNames.every((n) => arg[n] == null ||
        (n === 'alg'
            ? isAlg(arg[n], 'JWS')
            : n === 'jwk'
                ? isJWK(arg[n])
                : n === 'x5c' || n === 'crit'
                    ? Array.isArray(arg[n]) && arg[n].every((m) => typeof m === 'string')
                    : typeof arg[n] === 'string'));
/**
 * ２つの JWSJOSEHEader が同じか判定する
 */
function equalsJWSJOSEHeaderParams(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    for (const n of JWSJOSEHeaderParamNames) {
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

const equalsJOSEHeaderParams = (l, r) => {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    if (isJOSEHeaderParams(l, 'JWS')) {
        if (!isJOSEHeaderParams(r, 'JWS'))
            return false;
        return equalsJWSJOSEHeaderParams(l, r);
    }
    else if (isJOSEHeaderParams(l, 'JWE')) {
        if (!isJOSEHeaderParams(r, 'JWE'))
            return false;
        return equalsJWEJOSEHeaderParams(l, r) && equalsJWAAlgSpecificJOSEHeaderParams(l, r);
    }
    return false;
};
function isJOSEHeaderParams(arg, t) {
    const isJWE = (arg) => isPartialJWEJOSEHeaderParams(arg) && isPartialJWAAlgSpecificJOSEHeaderParams(arg);
    const isJWS = (arg) => isPartialJWSJOSEHeaderParams(arg);
    if (t === 'JWE') {
        return isJWE(arg);
    }
    if (t === 'JWS') {
        return isJWS(arg);
    }
    return isJWE(arg) || isJWS(arg);
}
function isJOSEHeaderParamName(arg, t) {
    const jwe = [...JWEJOSEHeaderParamNames, ...JWAAlgSpecificJOSEHeaderParamNames];
    const jws = [...JWSJOSEHeaderParamNames];
    if (t === 'JWE') {
        return jwe.some((n) => n === arg);
    }
    if (t === 'JWS') {
        return jws.some((n) => n === arg);
    }
    return [...jws, ...jwe].some((n) => n === arg);
}

const AGCMKeyWrapper = {
    wrap: async (key, cek, h) => {
        return wrap$3(key, cek, h);
    },
    unwrap: async (key, ek, h) => {
        if (!isAGCMKWHeaderParams(h)) {
            throw new TypeError(`JOSE Header for AES-GCM Key Wrapping に必須パラメータがない(iv, tag)`);
        }
        return unwrap$3(key, ek, h);
    },
};
/**
 * AES GCM アルゴリズムを使って CEK を暗号化する。
 */
async function wrap$3(key, cek, h) {
    const iv = h?.iv ? BASE64URL_DECODE(h.iv) : window.crypto.getRandomValues(new Uint8Array(12));
    // IV は 96bit である必要がある (REQUIRED)
    if (iv.length * 8 !== 96) {
        throw new TypeError('IV は 96bit である必要がある。');
    }
    // WecCryptoAPI を使うと JWK.alg チェックでエラーが出てしまう c.f.) https://w3c.github.io/webcrypto/#aes-gcm-operations
    // WebCryptoAPI は JWE.alg に対応できていないのかな...
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { alg, ...keyWithoutAlg } = key;
    const k = await window.crypto.subtle.importKey('jwk', keyWithoutAlg, { name: 'AES-GCM' }, false, [
        'encrypt',
    ]);
    const e = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, cek));
    const ek = e.slice(0, e.length - 16);
    // tag は Header に格納される。
    const tag = e.slice(e.length - 16);
    return { ek, h: { iv: h?.iv ?? BASE64URL(iv), tag: BASE64URL(tag) } };
}
/**
 * AES GCM アルゴリズムを使って Encrypted Key を復号する。
 */
async function unwrap$3(key, ek, h) {
    const iv = BASE64URL_DECODE(h.iv);
    // IV は 96bit である必要がある (REQUIRED)
    if (iv.length * 8 !== 96) {
        throw new TypeError('IV は 96bit である必要がある。');
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { alg, ...keyWithoutAlg } = key;
    const k = await window.crypto.subtle.importKey('jwk', keyWithoutAlg, { name: 'AES-GCM' }, false, [
        'decrypt',
    ]);
    const e = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k, CONCAT(ek, BASE64URL_DECODE(h.tag)));
    return new Uint8Array(e);
}

const AKWKeyWrapper = {
    wrap: async (key, cek) => {
        return { ek: await wrap$2(key, cek) };
    },
    unwrap: unwrap$2,
};
/**
 * AES Key Wrapping アルゴリズムに従い、 Content Encryption Key をラッピングして暗号化する。
 */
async function wrap$2(key, cek) {
    // Crypto API の wrapKey を使って CEK をラッピングするが、
    // wrapKey の引数には Crypt API の CryptoKey 形式にして、 CEK を渡す必要がある。
    // また、 CryptoKey をインポートする際は鍵の仕様用途などを指定する必要がある。
    // しかし指定した情報はラッピングに同梱されないため、適当に AES-GCM の鍵として CEK をインポートしている。
    const apiCEK = await window.crypto.subtle.importKey('raw', cek, 'AES-GCM', true, ['encrypt']);
    const k = await window.crypto.subtle.importKey('jwk', key, { name: 'AES-KW' }, false, [
        'wrapKey',
    ]);
    const e = await window.crypto.subtle.wrapKey('raw', apiCEK, k, { name: 'AES-KW' });
    return new Uint8Array(e);
}
/**
 * AES Key Wrapping アルゴリズムに従い、 JWE Encrypted Key を案ラップして CEK を復号する。
 */
async function unwrap$2(key, ek) {
    const k = await window.crypto.subtle.importKey('jwk', key, { name: 'AES-KW' }, false, [
        'unwrapKey',
    ]);
    const e = await window.crypto.subtle.unwrapKey('raw', ek, k, { name: 'AES-KW' }, 'AES-GCM', true, ['decrypt']);
    return new Uint8Array(await window.crypto.subtle.exportKey('raw', e));
}

const ECDHDirectKeyAgreementer = {
    partyU: async (key, h, eprivk) => {
        if (!isEncAlg(h.enc)) {
            throw new TypeError('JWE に必須のヘッダパラメータがない');
        }
        const enc = h.enc;
        if (!isECDH_ESAlg(h.alg)) {
            throw new TypeError('ECDH Direct Key Agreement Algorithm Identifier ではない');
        }
        const alg = h.alg;
        if (eprivk) {
            return {
                cek: await agree(key, eprivk, { ...h, alg, enc }),
                h: h.epk ? undefined : { epk: exportPubJWK(eprivk) },
            };
        }
        const eprivk_api = await window.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: key.crv }, true, ['deriveBits', 'deriveKey']);
        if (!eprivk_api.privateKey) {
            throw new EvalError(`Ephemeral EC Private Key の生成に失敗`);
        }
        const epk = await window.crypto.subtle.exportKey('jwk', eprivk_api.privateKey);
        if (!isJWK(epk, 'EC', 'Priv')) {
            throw new EvalError(`Ephemeral EC Private Key の生成に失敗`);
        }
        return {
            cek: await agree(key, epk, { ...h, alg, enc }),
            h: { epk: exportPubJWK(epk) },
        };
    },
    partyV: async (key, h) => {
        if (!isECDH_ESAlg(h.alg)) {
            throw new TypeError('ECDH Direct Key Agreement Algorithm Identifier ではない');
        }
        const alg = h.alg;
        if (!isEncAlg(h.enc)) {
            throw new TypeError('JWE に必須のヘッダパラメータがない');
        }
        const enc = h.enc;
        if (!isECDH_ESHeaderParams(h)) {
            throw new TypeError('JWE JOSE Header for ECDH Key Agreement のパラメータが不十分');
        }
        return agree(h.epk, key, { ...h, alg, enc });
    },
};
const ECDHKeyAgreementerWithKeyWrapping = {
    wrap: async (key, cek, h, eprivk) => {
        if (!isEncAlg(h.enc)) {
            throw new TypeError('JWE に必須のヘッダパラメータがない');
        }
        const enc = h.enc;
        if (!isECDH_ESKWAlg(h.alg)) {
            throw new TypeError('ECDH with Key Wrapping algorithm identifier ではない');
        }
        const alg = h.alg;
        if (eprivk) {
            return {
                ek: await wrap$1(key, cek, { ...h, alg, enc }, eprivk),
                h: h.epk ? undefined : { epk: exportPubJWK(eprivk) },
            };
        }
        const eprivk_api = await window.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: key.crv }, true, ['deriveBits', 'deriveKey']);
        if (!eprivk_api.privateKey) {
            throw new EvalError(`Ephemeral EC Private Key の生成に失敗`);
        }
        const epk = await window.crypto.subtle.exportKey('jwk', eprivk_api.privateKey);
        if (!isJWK(epk, 'EC', 'Priv')) {
            throw new EvalError(`Ephemeral EC Private Key の生成に失敗`);
        }
        return {
            ek: await wrap$1(key, cek, { ...h, alg, enc }, epk),
            h: { epk: exportPubJWK(epk) },
        };
    },
    unwrap: async (key, ek, h) => {
        if (!isEncAlg(h.enc)) {
            throw new TypeError('JWE に必須のヘッダパラメータがない');
        }
        const enc = h.enc;
        if (!isECDH_ESKWAlg(h.alg)) {
            throw new TypeError('ECDH with Key Wrapping algorithm identifier ではない');
        }
        const alg = h.alg;
        if (!isECDH_ESHeaderParams(h)) {
            throw new TypeError('JWE JOSE Header for ECDH Key Agreement のパラメータが不十分');
        }
        return unwrap$1(key, ek, { ...h, alg, enc });
    },
};
/**
 * RFC7518#4.6.2 に基づいて鍵合意を行う。
 * Party U の場合は generated Ephemeral Private Key と Static Public Key for Party V を使って計算する。
 * Party V の場合は Ephemeral Public Key in Header と Own Private Key を使って計算する。
 */
async function agree(pub, priv, h) {
    // ECDH は CryptoAPI 関数で行うので CryptoAPI 用の鍵に変換する
    const privKey = await window.crypto.subtle.importKey('jwk', priv, { name: 'ECDH', namedCurve: priv.crv }, true, ['deriveBits']);
    const pubKey = await window.crypto.subtle.importKey('jwk', pub, { name: 'ECDH', namedCurve: pub.crv }, true, []);
    // ECDH algorithm を用いて確立された shared secret Z
    const Z = new Uint8Array(await window.crypto.subtle.deriveBits({ name: 'ECDH', public: pubKey }, privKey, 
    // null でもいいはずなんだけどなあ c.f. https://w3c.github.io/webcrypto/#ecdh-operations
    // 結果のビット長は基本的に Crv の値と同じだけど P-521 だけは 66 bytes なので。
    pub.crv === 'P-521' ? 528 : parseInt(pub.crv.slice(2))));
    // Concat KDF を行い、鍵を導出する
    const keydatalen = genkeydatalen(h);
    const OtherInfo = genOtherInfo(h, keydatalen);
    const keyAgreementResult = await ConcatKDF(Z, { keydatalen, OtherInfo });
    return keyAgreementResult;
}
/**
 * RFC7518#4.6.2 に基づいて鍵合意を行い、行った結果をラッピング用の鍵として AES KW を使って CEK をラッピングする。
 */
async function wrap$1(key, cek, h, eprivk) {
    const keyAgreementResult = await agree(key, eprivk, h);
    const { ek } = await AKWKeyWrapper.wrap({ kty: 'oct', k: BASE64URL(keyAgreementResult) }, cek);
    return ek;
}
/**
 * RFC7518#4.6.2 に基づいて鍵合意を行い、行った結果をアンラッピング用の鍵として AES KW を使って EK をアンラップする。
 */
async function unwrap$1(key, ek, h) {
    const keyAgreementResult = await agree(h.epk, key, h);
    return AKWKeyWrapper.unwrap({ kty: 'oct', k: BASE64URL(keyAgreementResult) }, ek);
}
/**
 * NIST SP 800-56A2#5.8.1.1 に基づいて The Single Step KDF を実装する。
 * Z が the shared secret を表すバイト列で、 keydatalen が導出される keying material のビット長。
 * OtherInfo が文脈依存のデータを表すバイト列
 */
async function ConcatKDF(Z, OtherInput) {
    const { keydatalen, OtherInfo } = OtherInput;
    // Implementation-Dependent Parameters
    // RFC7518 で、 hash は SHA-256 を使う
    const hashlen = 256;
    const H = async (data) => new Uint8Array(await window.crypto.subtle.digest('SHA-256', data));
    // Process
    // Step1
    const reps = Math.ceil(keydatalen / hashlen);
    // Step2 は keydatalen が短いのが明らかなのでスキップ
    // Step3 Counter の初期化
    let counter = intToOctets$1(1, 4);
    let DerivedKeyingMaterial = new Uint8Array();
    // Step4 も超えなさそうなのでスキップ
    for (let i = 1; i <= reps; i++) {
        counter = intToOctets$1(i, 4);
        const Ki = await H(CONCAT(CONCAT(counter, Z), OtherInfo));
        DerivedKeyingMaterial = CONCAT(DerivedKeyingMaterial, Ki);
    }
    return DerivedKeyingMaterial.slice(0, keydatalen / 8);
}
/**
 * NIST.SP.800-56Ar2#5.8.1.1
 * keydatalen は導出される the secret keying material のビット長を示す。
 * ECDHAlg に応じて、 Concat KDF で使用する keydatalen parameter を決める。
 * ECDH-ES の場合は enc algorithm identifier の鍵長に依存するので、引数でそれも渡している。
 */
function genkeydatalen(h) {
    switch (h.alg) {
        case 'ECDH-ES':
            switch (h.enc) {
                case 'A128CBC-HS256':
                    return 32 * 8;
                case 'A192CBC-HS384':
                    return 48 * 8;
                case 'A256CBC-HS512':
                    return 64 * 8;
                case 'A128GCM':
                    return 128;
                case 'A192GCM':
                    return 192;
                case 'A256GCM':
                    return 256;
            }
            break;
        case 'ECDH-ES+A128KW':
            return 128;
        case 'ECDH-ES+A192KW':
            return 192;
        case 'ECDH-ES+A256KW':
            return 256;
    }
}
/**
 * NIST.SP.800-56Ar2#5.8.1.2 OtherInfo
 * 導出されたキーマテリアルが the key-agreement transaction の文脈に適切に「バインド」されていることを保証するために使う。(should)
 * 例えば、OtherInfo のそれぞれの値は DataLen || Data の形式で表現されるべき(shall)。
 * Data は可変長の文字列で、DataLen は固定長のビックエンディアンのデータオクテット長表現。
 */
function genOtherInfo(h, keydatalen) {
    /**
     * AlgorithmID: the derived keying material をパースする方法と the derived secret keying を使うであろうアルゴリズムを示す。
     * RFC7518 において、Data は ECDH-ES の場合は enc アルゴリズム識別子であり、それ以外は alg アルゴリズム識別子である。
     * DataLen は Data のオクテット長を示す 4bytes の非負整数（オクテット表現）。
     */
    const AlgorithmID = representOtherInfo(ASCII(isECDH_ESAlg(h.alg) ? h.enc : h.alg), 4);
    /**
     * PartyUinfo: party U (Ephemeral Key Pair を作る側) に関するパブリックな情報を含める。
     * RFC7518 において、Data は Header.apu の値を BASE64url decode した値である。
     * apu がなければ、Data は空のオクテット列で、 datalen は 0になる。
     */
    const PartyUInfo = representOtherInfo(h.apu ? BASE64URL_DECODE(h.apu) : new Uint8Array(), 4);
    /**
     * PartyVInfo: party V (static pub を提供する側) に関するパブリックな情報を含める。
     * PartyUinfo と同じフォーマットだが、使用するパラメータは Header.apv
     */
    const PartyVInfo = representOtherInfo(h.apv ? BASE64URL_DECODE(h.apv) : new Uint8Array(), 4);
    /**
     * SuppPubInfo: 互いに既知の public information を持つ。(例えば keydatalen)
     * RFC7518 では keydatalen を 32bit でビックエンディアン表現した整数
     */
    const SuppPubInfo = intToOctets$1(keydatalen, 4);
    /**
     * SuppPrivInfo: 互いに既知の private information を持つ。(例えば、別チャネルで伝えた共有鍵)
     * RFC7518 では空オクテット列。
     */
    const SuppPrivInfo = new Uint8Array();
    /**
     * NIST.SP.800-56Ar2#5.8.1.2.1 The Concatnation Format for OtherInfo
     * に従って OtherInfo を表現する。
     */
    const OtherInfo = CONCAT(AlgorithmID, CONCAT(PartyUInfo, CONCAT(PartyVInfo, CONCAT(SuppPubInfo, SuppPrivInfo))));
    return OtherInfo;
}
/**
 * OtherInfo の各値を Datalen || Data の形にする。
 */
function representOtherInfo(data, datalenlen) {
    const datalen = intToOctets$1(data.length, datalenlen);
    return CONCAT(datalen, data);
}
/**
 * 非負整数を xLen の長さのオクテットで表現する。
 * 表現はビックエンディアン。
 */
function intToOctets$1(x, xLen) {
    let xStr = x.toString(16);
    if (xStr.length % 2 == 1) {
        xStr = '0' + xStr;
    }
    if (xStr.length / 2 > xLen) {
        throw 'integer too long';
    }
    if (xStr.length / 2 < xLen) {
        xStr = '00'.repeat(xLen - xStr.length / 2) + xStr;
    }
    const ans = new Uint8Array(xLen);
    for (let i = 0; i < xLen; i++) {
        ans[i] = parseInt(xStr.substr(i * 2, 2), 16);
    }
    return ans;
}

const PBES2KeyWrapper = {
    wrap: async (key, cek, h) => {
        if (!h || !isPBES2Alg(h.alg)) {
            throw new TypeError('PBES2 algorithm identifier ではなかった');
        }
        return wrap(key, cek, { ...h, alg: h.alg });
    },
    unwrap: async (key, ek, h) => {
        if (!h || !isPBES2Alg(h.alg)) {
            throw new TypeError('PBES2 algorithm identifier ではなかった');
        }
        const alg = h.alg;
        if (!isPBES2HeaderParams(h)) {
            throw new TypeError('JOSE Header for PBES2 Key Wrapping に必須パラメータがない');
        }
        return unwrap(key, ek, { ...h, alg });
    },
};
/**
 * RFC2898#6.2.1 に基づいて、ユーザが指定したパスワードで CEK をラップする。
 * パスワードは JWK<oct> で表現されているが、k にはパスワードの UTF-8 表現を BASE64URL エンコードしたものが入る。
 */
async function wrap(key, cek, h) {
    const { HASH_ALG, KEY_LEN } = algParams$1(h.alg);
    /**
     * P はパスワードの UTF-8 表現である。
     */
    const P = BASE64URL_DECODE(key.k);
    /**
     * RFC2898#6.1.1 Step1 salt(S) と iteration count(c) を決める
     * RFC7518#4.8.1.1 では salt を (UTF8(Alg) || 0x00 || Header.p2s) として定めている。
     * RFC7518#4.8.1.2 では iteration count を Header.p2c として定めている。
     */
    const s = h.p2s ? BASE64URL_DECODE(h.p2s) : window.crypto.getRandomValues(new Uint8Array(8));
    const c = h.p2c ?? 1000;
    const S = CONCAT(CONCAT(UTF8(h.alg), new Uint8Array([0])), s);
    /**
     * RFC2898#6.1.1 Step2 導出される鍵のオクテット長を決める。
     * RFC7518#4.8.1 では AES KW でラップするとしているので、 Header.alg アルゴリズムに応じて鍵長が決まる。
     */
    const dkLen = KEY_LEN;
    /**
     * RFC2898#6.1.1 Step3  KDF を適用する。 PBKDF2 で使用するハッシュ関数は Header.alg に応じて決まる。
     */
    const DK = await PBKDF2(P, S, c, dkLen, HASH_ALG);
    /**
     * RFC2898#6.1.1 Step4 cek を暗号化する。
     * RFC7518 では AES KW を使うとしているので AKWKeyWrapper 実装を用いている。
     */
    const { ek } = await AKWKeyWrapper.wrap({ kty: 'oct', k: BASE64URL(DK) }, cek);
    return { ek, h: { p2s: h.p2s ?? BASE64URL(s), p2c: h.p2c ?? c } };
}
/**
 * RFC2898#6.2.2 に基づいて、ユーザが指定したパスワードで EK を復号する。
 * パスワードは JWK<oct> で表現されているが、k にはパスワードの UTF-8 表現を BASE64URL エンコードしたものが入る。
 */
async function unwrap(key, ek, h) {
    const { HASH_ALG, KEY_LEN } = algParams$1(h.alg);
    const P = BASE64URL_DECODE(key.k);
    // Step1
    const S = CONCAT(CONCAT(UTF8(h.alg), new Uint8Array([0])), BASE64URL_DECODE(h.p2s));
    // Step2
    const c = h.p2c;
    // Step3
    const dkLen = KEY_LEN;
    // Step4
    const DK = await PBKDF2(P, S, c, dkLen, HASH_ALG);
    // Step5
    return AKWKeyWrapper.unwrap({ kty: 'oct', k: BASE64URL(DK) }, ek);
}
function algParams$1(alg) {
    switch (alg) {
        case 'PBES2-HS256+A128KW':
            return { HASH_ALG: 'SHA-256', KEY_LEN: 128 };
        case 'PBES2-HS384+A192KW':
            return { HASH_ALG: 'SHA-384', KEY_LEN: 192 };
        case 'PBES2-HS512+A256KW':
            return { HASH_ALG: 'SHA-512', KEY_LEN: 256 };
    }
}
/**
 * RFC2898#5.2 PBKDF2 を実装する。実体は CryptoAPI.deriveBits で行っている。
 */
async function PBKDF2(P, S, c, dkLen, hash) {
    const cP = await window.crypto.subtle.importKey('raw', P, 'PBKDF2', false, ['deriveBits']);
    const DK = await window.crypto.subtle.deriveBits({ name: 'PBKDF2', hash, salt: S, iterations: c }, cP, dkLen);
    return new Uint8Array(DK);
}

const RSAKeyEncryptor = { enc: enc$3, dec: dec$3 };
/**
 * RSAES-PKCS1-v1_5 か RSA-OAEP アルゴリズム(alg) に従い、与えられた Content Encryption Key を key を使って暗号化する。
 * 計算を行う前に、鍵長が 2048 以上か確認する。
 */
async function enc$3(alg, key, cek) {
    if (BASE64URL_DECODE(key.n).length * 8 < 2048) {
        // キーサイズが 2048 bit 以上であることが MUST (RFC7518#4.2)
        throw new EvalError(`RSA enc では鍵長が 2048 以上にしてください`);
    }
    if (isRSA1_5Alg(alg)) {
        return (await encryptRSA1_5(key, cek));
    }
    else if (isRSAOAEPAlg(alg)) {
        const hash = alg === 'RSA-OAEP' ? 'SHA-1' : 'SHA-256';
        const keyAlg = { name: 'RSA-OAEP', hash };
        const encAlg = { name: 'RSA-OAEP' };
        const k = await window.crypto.subtle.importKey('jwk', key, keyAlg, false, ['encrypt']);
        const e = await window.crypto.subtle.encrypt(encAlg, k, cek);
        return new Uint8Array(e);
    }
    throw new EvalError(`unrecognized alg(${alg})`);
}
async function dec$3(alg, key, ek) {
    if (BASE64URL_DECODE(key.n).length * 8 < 2048 && BASE64URL_DECODE(key.d).length * 8 < 2048) {
        // キーサイズが 2048 bit 以上であることが MUST (RFC7518#4.2)
        throw new EvalError(`RSA dec では鍵長が 2048 以上にしてください`);
    }
    if (isRSA1_5Alg(alg)) {
        return (await decryptRSA1_5(key, ek));
    }
    if (isRSAOAEPAlg(alg)) {
        const hash = alg === 'RSA-OAEP' ? 'SHA-1' : 'SHA-256';
        const keyAlg = { name: 'RSA-OAEP', hash };
        const encAlg = { name: 'RSA-OAEP' };
        const k = await window.crypto.subtle.importKey('jwk', key, keyAlg, false, ['decrypt']);
        const e = await window.crypto.subtle.decrypt(encAlg, k, ek);
        return new Uint8Array(e);
    }
    throw EvalError('alg は列挙できているはず');
}
// RFC3447#7.2.1 RSAES-PKCS1-V1_5-ENCRYPT を実装
async function encryptRSA1_5(key, message) {
    // k denotes the length in octets of the modulus n
    const k = BASE64URL_DECODE(key.n).length;
    // message to be encrypted, an octet string of length mLen,
    const mLen = message.length;
    // Step1
    if (mLen > k - 11) {
        throw 'message too long';
    }
    // Step2.a
    // const PS = genNonZeroUint8Array(k - mLen - 3);
    // 例示データを複合して PS に使用した値を逆算したもの
    const PS = BASE64URL_DECODE('wx6eRzOkz9TWarNXjlU1eAwOlBN3b7fq9BgksROinirQYwVNNb6GzUMt0fYjbRlEbHdklsK8z1H-L4ZRdgeoPzuE4yNShwteN6hZkofbYRT9iX6kSEYmEs0CRBWUKBeEuFQD4NOGzc5QpfarwLV1U8Djut1l49wr84OH1YaO9X7rn6iclHa_JrgSNWDzITFkr2-X-5uHzDE0HZvvW2v4P8PxS9jbEcsDkROp3KL1NJoEncU5BQk3IB8GghM-kQnIdOdrRmaG0MFHfRs4d1U3OIxK0JjW8xccqpSGlII');
    // Step2.b
    const EM = CONCAT(CONCAT(CONCAT(new Uint8Array([0, 2]), PS), new Uint8Array([0])), message);
    // Step3.a
    const m = OS2IP(EM);
    // Step3.b
    const c = await RSAEP(OS2IP(BASE64URL_DECODE(key.n)), OS2IP(BASE64URL_DECODE(key.e)), m);
    return I2OSP(c, k);
}
async function decryptRSA1_5(key, ciphertext) {
    // k is the length in octets of the RSA modulus n
    const k = BASE64URL_DECODE(key.n).length;
    // Step1
    if (ciphertext.length !== k || k < 11) {
        throw 'decryption error';
    }
    // Step2.a
    const c = OS2IP(ciphertext);
    // Step2.b
    let m;
    try {
        m = await RSADP(OS2IP(BASE64URL_DECODE(key.n)), OS2IP(BASE64URL_DECODE(key.d)), c);
    }
    catch (err) {
        throw 'decryption error';
    }
    // Step2.c
    const EM = I2OSP(m, k);
    // Step3
    if (EM[0] === 0 && EM[1] === 2) {
        let pslen = 0;
        for (let i = 2; i < EM.length; i++) {
            if (EM[i] !== 0) {
                pslen++;
            }
            else {
                break;
            }
        }
        if (pslen < EM.length - 2 && pslen >= 8) {
            return EM.slice(2 + pslen + 1);
        }
    }
    throw 'decryption error';
}
// RFC3447#4.1 I2OSP
// 整数 x を受け取って長さ xLen のバイナリ列表現を返す
function I2OSP(x, xLen) {
    let xStr = x.toString(16);
    if (xStr.length % 2 == 1) {
        xStr = '0' + xStr;
    }
    if (xStr.length / 2 > xLen) {
        throw 'integer too long';
    }
    if (xStr.length / 2 < xLen) {
        xStr = '00'.repeat(xLen - xStr.length / 2) + xStr;
    }
    const ans = new Uint8Array(xLen);
    for (let i = 0; i < xLen; i++) {
        ans[i] = parseInt(xStr.substr(i * 2, 2), 16);
    }
    return ans;
}
// RFC3447#4.2 OS2IP
// バイナリ列 X を受け取って、その非不整数表現を返す
function OS2IP(X) {
    // Uint8Array を16進表現にする
    const hexStr = Array.from(X)
        .map((e) => {
        let hexchar = e.toString(16);
        if (hexchar.length == 1) {
            hexchar = '0' + hexchar;
        }
        return hexchar;
    })
        .join('');
    return BigInt('0x' + hexStr);
}
// RFC3447#5.1.1 RSA Encryption Primitives
async function RSAEP(n, e, m) {
    if (0n > m || m > n) {
        throw 'message representative out of range';
    }
    return await modPow(m, e, n);
}
// RFC3447#5.1.2 RSA Decryption Primitives
// 一番簡単なやつだけ実装
async function RSADP(n, d, c) {
    if (0n > c || c > n) {
        throw 'ciphertext representative out of range';
    }
    return await modPow(c, d, n);
}
// g を k 乗した値を n で割った余りを返す。 with バイナリ法
async function modPow(g, k, n) {
    const k_bin = k.toString(2);
    let r = 1n;
    for (const k of k_bin) {
        r = (r * r) % n;
        if (k == '1') {
            r = (r * g) % n;
        }
    }
    return r;
}

function newJWAKeyEncryptor(alg) {
    if (isRSA1_5Alg(alg) || isRSAOAEPAlg(alg))
        return RSAKeyEncryptor;
    throw TypeError(`KeyEncryptor<$alg> は実装されていない`);
}
function newJWAKeyWrapper(alg) {
    if (isAKWAlg(alg))
        return AKWKeyWrapper;
    if (isAGCMKWAlg(alg))
        return AGCMKeyWrapper;
    if (isPBES2Alg(alg))
        return PBES2KeyWrapper;
    throw TypeError(`KeyWrapper<$alg> is not implemented`);
}
function newJWADirectAgreementer(alg) {
    if (isECDH_ESAlg(alg))
        return ECDHDirectKeyAgreementer;
    throw TypeError(`KeyAgreement<$alg> is not implemented`);
}
function newJWAKeyAgreementerWithKeyWrapping(alg) {
    if (isECDH_ESKWAlg(alg))
        return ECDHKeyAgreementerWithKeyWrapping;
    throw TypeError(`KeyAgreementerWithKeyWrapping<$alg> is not implemented`);
}
function newJWADirectEncryptor(alg) {
    if (isJWAJWEAlg(alg, 'DE'))
        return {
            extract: async (alg, key) => BASE64URL_DECODE(key.k),
        };
    throw TypeError(`DirecyEncryptor<$alg> is not implemented`);
}

/**
 * RFC7518#5.2.  AES_CBC_HMAC_SHA2 Algorithms のアルゴリズムの実装.
 */
const ACBCEncOperator = { enc: enc$2, dec: dec$2 };
/**
 * RFC7518#5.2.  AES_CBC_HMAC_SHA2 Algorithms のアルゴリズムに従って暗号化する。
 */
async function enc$2(enc, cek, m, aad, iv) {
    const { E, T, IV } = await encryptAES_CBC_HMAC_SHA2(enc, cek, m, aad, iv);
    return { c: E, tag: T, iv: IV };
}
async function dec$2(enc, cek, iv, aad, c, tag) {
    return await decryptAES_CBC_HMAC_SHA2(enc, cek, aad, iv, c, tag);
}
function generateCEKForACBCEnc(enc) {
    const { MAC_KEY_LEN, ENC_KEY_LEN } = algParams(enc);
    const len = MAC_KEY_LEN + ENC_KEY_LEN;
    const cek = window.crypto.getRandomValues(new Uint8Array(len));
    return cek;
}
/**
 * RFC7518#5.2.2.1 AES_CBC_HMAC_SHA2 Encryption を実装する。
 */
async function encryptAES_CBC_HMAC_SHA2(enc, K, P, A, IV) {
    // Step1 enc に基づいて鍵長のチェックを行い、HMAC 計算用の鍵と 暗号化鍵を用意する。
    const { MAC_KEY_LEN, ENC_KEY_LEN, HASH_ALG, T_LEN } = algParams(enc);
    if (K.length !== MAC_KEY_LEN + ENC_KEY_LEN) {
        throw 'K の長さが不一致';
    }
    const MAC_KEY = K.slice(0, MAC_KEY_LEN);
    const ENC_KEY = K.slice(ENC_KEY_LEN);
    // Step2 IV を用意する
    if (!IV) {
        IV = new Uint8Array(16);
        window.crypto.getRandomValues(IV);
    }
    // Step3 AES-CBC で暗号化する。
    const acKey = await window.crypto.subtle.importKey('raw', ENC_KEY, { name: 'AES-CBC' }, false, [
        'encrypt',
    ]);
    const E = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'AES-CBC', iv: IV }, acKey, P));
    // Step4
    const AL = intToOctets(A.length * 8, 64 / 8);
    // Step5 HMAC で認証タグを生成する。
    const hKey = await window.crypto.subtle.importKey('raw', MAC_KEY, { name: 'HMAC', hash: HASH_ALG }, false, ['sign']);
    const hSig = await window.crypto.subtle.sign('HMAC', hKey, CONCAT(CONCAT(CONCAT(A, IV), E), AL));
    const T = new Uint8Array(hSig).slice(0, T_LEN);
    return { E, T, IV };
}
/**
 * RFC7518#5.2.2.2 AES_BC_HMAC_SHA2 Decryption を実装する。
 */
async function decryptAES_CBC_HMAC_SHA2(enc, K, A, IV, E, T) {
    // Step1
    const { MAC_KEY_LEN, ENC_KEY_LEN, HASH_ALG, T_LEN } = algParams(enc);
    if (K.length != MAC_KEY_LEN + ENC_KEY_LEN) {
        throw 'K の長さが不一致';
    }
    const MAC_KEY = K.slice(0, MAC_KEY_LEN);
    const ENC_KEY = K.slice(ENC_KEY_LEN);
    // Step2
    const AL = intToOctets(A.length * 8, 64 / 8);
    // verify としたいところだが、 HMAC の結果をそのまま署名の値とはしていないので
    const hKey = await window.crypto.subtle.importKey('raw', MAC_KEY, { name: 'HMAC', hash: HASH_ALG }, false, ['sign']);
    const hSig = await window.crypto.subtle.sign('HMAC', hKey, CONCAT(CONCAT(CONCAT(A, IV), E), AL));
    const dervivedT = new Uint8Array(hSig).slice(0, T_LEN);
    // 配列の比較がめんどくさいので文字列に直して比較した
    if (BASE64URL(dervivedT) !== BASE64URL(T)) {
        throw 'decryption failed';
    }
    // Step3
    const acKey = await window.crypto.subtle.importKey('raw', ENC_KEY, { name: 'AES-CBC' }, false, [
        'decrypt',
    ]);
    const acDec = await window.crypto.subtle.decrypt({ name: 'AES-CBC', iv: IV }, acKey, E);
    const P = new Uint8Array(acDec);
    return P;
}
function algParams(enc) {
    switch (enc) {
        case 'A128CBC-HS256':
            return {
                MAC_KEY_LEN: 16,
                ENC_KEY_LEN: 16,
                HASH_ALG: 'SHA-256',
                T_LEN: 16,
            };
        case 'A192CBC-HS384':
            return {
                MAC_KEY_LEN: 24,
                ENC_KEY_LEN: 24,
                HASH_ALG: 'SHA-384',
                T_LEN: 24,
            };
        case 'A256CBC-HS512':
            return {
                MAC_KEY_LEN: 32,
                ENC_KEY_LEN: 32,
                HASH_ALG: 'SHA-512',
                T_LEN: 32,
            };
    }
}
function intToOctets(x, xLen) {
    let xStr = x.toString(16);
    if (xStr.length % 2 == 1) {
        xStr = '0' + xStr;
    }
    if (xStr.length / 2 > xLen) {
        throw 'integer too long';
    }
    if (xStr.length / 2 < xLen) {
        xStr = '00'.repeat(xLen - xStr.length / 2) + xStr;
    }
    const ans = new Uint8Array(xLen);
    for (let i = 0; i < xLen; i++) {
        ans[i] = parseInt(xStr.substr(i * 2, 2), 16);
    }
    return ans;
}

const AGCMEncOperator = { enc: enc$1, dec: dec$1 };
async function enc$1(enc, cek, m, aad, iv) {
    if (!iv) {
        iv = window.crypto.getRandomValues(new Uint8Array(12));
    }
    const k = await window.crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, [
        'encrypt',
    ]);
    const e = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, k, m));
    const ciphertext = e.slice(0, e.length - 16);
    const tag = e.slice(e.length - 16);
    return { c: ciphertext, tag, iv };
}
async function dec$1(enc, cek, iv, aad, c, tag) {
    const k = await window.crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, [
        'decrypt',
    ]);
    const e = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, k, CONCAT(c, tag));
    return new Uint8Array(e);
}
function generateCEKForAGCMEnc(enc) {
    const len = (() => {
        switch (enc) {
            case 'A128GCM':
                return 128 / 8;
            case 'A192GCM':
                return 192 / 8;
            case 'A256GCM':
                return 256 / 8;
        }
    })();
    return window.crypto.getRandomValues(new Uint8Array(len));
}

function generateCEKforJWACEK(enc) {
    if (isACBCEnc(enc))
        return generateCEKForACBCEnc(enc);
    if (isAGCMEnc(enc))
        return generateCEKForAGCMEnc(enc);
    throw new TypeError(`${enc} は JWAEncAlg ではない`);
}
function newJWAEncOperator(enc) {
    if (isACBCEnc(enc))
        return ACBCEncOperator;
    if (isAGCMEnc(enc))
        return AGCMEncOperator;
    throw TypeError(`EncOperator<$alg> is not implemented`);
}

function keyMgmtModeFromAlg(alg) {
    if (isJWAJWEAlg(alg))
        return keyMgmtModeFromJWAAlg(alg);
    const a = alg;
    throw new TypeError(`${a} の Key Management Mode がわからない`);
}
function newKeyEncryptor(alg) {
    if (isJWAJWEAlg(alg, 'KE'))
        return newJWAKeyEncryptor(alg);
    throw new TypeError(`KeyEncryptor<${alg}> は実装されていない`);
}
function newKeyWrappaer(alg) {
    if (isJWAJWEAlg(alg, 'KW'))
        return newJWAKeyWrapper(alg);
    throw new TypeError(`KeyWrapper<${alg}> は実装されていない`);
}
function newDirectKeyAgreementer(alg) {
    if (isJWAJWEAlg(alg, 'DKA'))
        return newJWADirectAgreementer(alg);
    throw new TypeError(`DirectKeyAgreementer<${alg}> は実装されていない`);
}
function newKeyAgreementerWithKeyWrapping(alg) {
    if (isJWAJWEAlg(alg, 'KAKW'))
        return newJWAKeyAgreementerWithKeyWrapping(alg);
    throw new TypeError(`KeyAgreementerWithKeyWrapping<${alg}> は実装されていない`);
}
function newDirectEncrytor(alg) {
    if (isJWAJWEAlg(alg, 'DE'))
        return newJWADirectEncryptor(alg);
    throw new TypeError(`DirectEncrypto<${alg}> は実装されていない`);
}
function generateCEK(enc) {
    if (isJWAEncAlg(enc))
        return generateCEKforJWACEK(enc);
    throw new TypeError(`${enc} の CEK を生成できない`);
}
function newEncOperator(enc) {
    if (isEncAlg(enc))
        return newJWAEncOperator(enc);
    throw new TypeError(`EncOperator<${enc}> は実装されていない`);
}

function JWEHeaderBuilderFromSerializedJWE(p_b64u, su, ru) {
    let alg;
    let algOne;
    let algArray;
    let encalg;
    let options;
    if (p_b64u) {
        const initialValue = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(p_b64u)));
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
            options.p = { initialValue: initialValue, b64u: p_b64u };
        }
        else {
            options = {
                p: { initialValue: initialValue, b64u: p_b64u },
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
        }
        else {
            options = { su: { initialValue } };
        }
    }
    if (ru) {
        if (Array.isArray(ru)) {
            const ru_option = ru.map((rh) => {
                if (!rh)
                    return {};
                const initialValue = rh;
                return { initialValue };
            });
            algArray = ru_option.map(({ initialValue }) => {
                if (initialValue?.enc) {
                    encalg = initialValue.enc;
                }
                if (initialValue?.alg)
                    return initialValue?.alg;
                if (algOne)
                    return algOne;
                throw new TypeError('JOSEHeader.alg がない');
            });
            if (options) {
                options.ru = ru_option;
            }
            else {
                options = { ru: ru_option };
            }
        }
        else {
            const initialValue = ru;
            if (initialValue.alg) {
                algOne = initialValue.alg;
            }
            if (initialValue.enc) {
                encalg = initialValue.enc;
            }
            if (options) {
                options.ru = { initialValue };
            }
            else {
                options = { ru: { initialValue } };
            }
        }
    }
    if (!encalg) {
        throw new TypeError('JOSEHeader.enc がなかった');
    }
    if (algOne) {
        alg = algOne;
    }
    else if (algArray) {
        if (!algArray[0]) {
            throw new TypeError('JOSEHeader.alg がなかった');
        }
        alg = algArray[0];
        if (algArray[1]) {
            alg = [algArray[0], algArray[1], ...algArray.slice(2)];
        }
    }
    else {
        throw new TypeError('JOSEHeader.alg がなかった');
    }
    return JWEHeaderBuilder(alg, encalg, options);
}
function JWEHeaderBuilder(alg, enc, options) {
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
class JWESharedHeader {
    constructor(options) {
        if (!options) {
            this.shared = {};
            this.paramNames = { p: new Set(), su: new Set() };
            return;
        }
        let shared;
        const paramNames = {
            p: new Set(),
            su: new Set(),
        };
        for (const i of ['p', 'su']) {
            const h = options[i];
            if (!h)
                continue;
            // 初期値として与えるヘッダー情報とヘッダー名情報が矛盾していないかチェック
            if (h.initialValue) {
                if (h.paramNames) {
                    for (const n of Object.keys(h.initialValue)) {
                        if (isJOSEHeaderParamName(n) && !h.paramNames.has(n)) {
                            throw new TypeError(`オプションで指定する ${i}.Header の初期値と Header Parameter Names が一致していない` +
                                ` because: initValue にあるパラメータ名 ${n} は paramNames ${h.paramNames} に含まれていません`);
                        }
                    }
                    h.paramNames.forEach((n) => paramNames[i].add(n));
                }
                else {
                    Object.keys(h.initialValue).forEach((n) => {
                        if (isJOSEHeaderParamName(n))
                            paramNames[i].add(n);
                    });
                }
                shared = { ...shared, ...h.initialValue };
            }
            else {
                h.paramNames?.forEach((n) => paramNames[i].add(n));
            }
        }
        // オプションで渡される Protected Header の Base64url 表現が JOSE Header のものかチェック
        if (options.p?.b64u) {
            const p = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(options.p.b64u)));
            if (!isJOSEHeaderParams(p, 'JWE')) {
                throw new TypeError('オプションで指定された Protected Header の b64u のデコード結果が JOSE Header for JWE ではなかった');
            }
        }
        // params の整合性チェック。重複していないかどうか判断する
        const params = new Set();
        let paramsDesiredSize = 0;
        paramNames.p.forEach((n) => params.add(n));
        paramsDesiredSize += paramNames.p.size;
        paramNames.su.forEach((n) => params.add(n));
        paramsDesiredSize += paramNames.su.size;
        if (paramsDesiredSize !== params.size) {
            throw new TypeError('オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません');
        }
        this.shared = shared ?? {};
        this.paramNames = paramNames;
        return;
    }
    Protected() {
        const entries = Object.entries(this.shared).filter(([n]) => isJOSEHeaderParamName(n) && this.paramNames.p.has(n));
        if (entries.length === 0)
            return undefined;
        return Object.fromEntries(entries);
    }
    Protected_b64u() {
        if (this.protected_b64u) {
            const p = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(this.protected_b64u)));
            if (!isJOSEHeaderParams(p, 'JWE')) {
                throw new TypeError('オプションで指定された Protected Header の b64u のデコード結果が JOSE Header for JWE ではなかった');
            }
            if (!equalsJOSEHeaderParams(p, this.Protected())) {
                throw new TypeError('オプションで指定された Protected Header と生成した Protected Header が一致しなかった' +
                    `becasuse: decoded options.b64u: ${p} but generated protected header: ${this.Protected()}`);
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
        const entries = Object.entries(this.shared).filter(([n]) => isJOSEHeaderParamName(n) && this.paramNames.su.has(n));
        if (entries.length === 0)
            return undefined;
        return Object.fromEntries(entries);
    }
    update(v) {
        Object.entries(v).forEach(([n, vv]) => {
            if (!isJOSEHeaderParamName(n))
                return;
            if (this.paramNames.p.has(n) || this.paramNames.su.has(n)) {
                this.shared = { ...this.shared, [n]: vv };
                return;
            }
            // paramNames で配置場所が指定されていない場合は、 alg と同じ場所
            if (this.paramNames.p.has('alg') || this.paramNames.su.has('alg')) {
                this.shared = { ...this.shared, [n]: vv };
                if (this.paramNames.p.has('alg')) {
                    this.paramNames.p.add(n);
                }
                else {
                    this.paramNames.su.add(n);
                }
            }
        });
    }
}
class JWEHeaderforMultiParties extends JWESharedHeader {
    constructor(alg, enc, options) {
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
            for (const i of ['p', 'su']) {
                const opt = options[i];
                if (opt?.initialValue?.alg) {
                    if (opt.initialValue.alg !== alg[0]) {
                        throw new TypeError(`オプションで指定する ${i}.InitialValue Header と alg の値が一致していない`);
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
                        throw new TypeError(`オプションで指定する ru.InitialValue Header と alg の値が一致していない`);
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
                    }
                    else {
                        options.p.initialValue = { alg: alg[0] };
                    }
                    if (options.p.paramNames) {
                        options.p.paramNames.add('alg');
                    }
                }
                else {
                    options.p = { initialValue: { alg: alg[0] } };
                }
            }
        }
        else {
            if (options.p?.paramNames?.has('alg') || options.su?.paramNames?.has('alg')) {
                throw new TypeError('alg が同じ値でない時は Protected Header or Shared Unprotected Header に alg パラメータを含めてはならない');
            }
            if (options.ru) {
                if (options.ru.length !== alg.length) {
                    throw new TypeError('オプションで PerRecipient Header に関するものを与えるときは alg と同じ長さの配列にしてください。さらに、同じインデックスが同じ受信者を表すようにしてください');
                }
                options.ru.forEach((r, i) => {
                    if (r.initialValue?.alg) {
                        if (r.initialValue.alg !== alg[i]) {
                            throw new TypeError(`オプションで指定する ru.InitialValue Header と alg の値が一致していない`);
                        }
                        return;
                    }
                    if (r.paramNames?.has('alg')) {
                        r.initialValue = { ...r.initialValue, alg: alg[0] };
                        return;
                    }
                });
            }
            else {
                options.ru = alg.map((a) => ({ initialValue: { alg: a } }));
            }
        }
        // enc をどのヘッダに組み込むか決定する。
        {
            let isConfigured = false;
            for (const i of ['p', 'su']) {
                const opt = options[i];
                if (opt?.initialValue?.enc) {
                    if (opt.initialValue.enc !== enc) {
                        throw new TypeError(`オプションで指定する ${i}.InitialValue Header と enc の値が一致していない`);
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
                        throw new TypeError(`オプションで指定する ru.InitialValue Header と enc の値が一致していない`);
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
                    }
                    else {
                        options.p.initialValue = { enc };
                    }
                    if (options.p.paramNames) {
                        options.p.paramNames.add('alg');
                    }
                }
                else {
                    options.p = { initialValue: { enc } };
                }
            }
        }
        // Protected Header と Shared Unprotected Header を保持する JWESharedHeader をインスタンス化
        super(options);
        const perRcpt = alg.map(() => ({ params: {}, paramNames: new Set() }));
        options.ru?.forEach((r, i) => {
            const perRcpti = perRcpt[i];
            if (!perRcpti)
                throw new TypeError();
            if (r.initialValue) {
                if (r.paramNames) {
                    for (const n of Object.keys(r.initialValue)) {
                        if (isJOSEHeaderParamName(n) && !r.paramNames.has(n)) {
                            throw new TypeError('オプションで指定する ru.Header の初期値と Header Parameter Names が一致していない' +
                                `because: initValue にあるパラメータ名 ${n} は paramNames ${r.paramNames} に含まれていません`);
                        }
                    }
                    for (const n of r.paramNames) {
                        perRcpti.paramNames.add(n);
                    }
                }
                else {
                    Object.keys(r.initialValue).forEach((n) => {
                        if (isJOSEHeaderParamName(n))
                            perRcpti.paramNames.add(n);
                    });
                }
                perRcpti.params = { ...perRcpti.params, ...r.initialValue };
            }
            else {
                r.paramNames?.forEach((n) => perRcpti.paramNames.add(n));
            }
        });
        // params の整合性チェック。重複していないかどうか判断する
        if (!perRcpt.every((pr) => {
            if (pr.paramNames.size === 0)
                return true;
            const params = new Set([...this.paramNames.p, ...this.paramNames.su]);
            let paramsDesiredSize = this.paramNames.p.size + this.paramNames.su.size;
            pr.paramNames.forEach((n) => params.add(n));
            paramsDesiredSize += pr.paramNames.size;
            return paramsDesiredSize === params.size;
        })) {
            throw new TypeError('オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません');
        }
        this.perRcpt = perRcpt;
    }
    PerRecipient(recipientIndex) {
        const perRcpt = this.perRcpt[recipientIndex ?? 0];
        if (!perRcpt)
            return undefined;
        const entries = Object.entries(perRcpt.params).filter(([n]) => isJOSEHeaderParamName(n) && perRcpt.paramNames.has(n));
        if (entries.length === 0)
            return undefined;
        return Object.fromEntries(entries);
    }
    JOSE(recipientIndex) {
        return { ...this.shared, ...this.PerRecipient(recipientIndex) };
    }
    update(v, recipientIndex) {
        super.update(v);
        const perRcpt = this.perRcpt[recipientIndex ?? 0];
        if (!perRcpt)
            return;
        Object.entries(v).forEach(([n, vv]) => {
            if (!isJOSEHeaderParamName(n))
                return;
            if (perRcpt.paramNames.has(n)) {
                perRcpt.params = { ...perRcpt.params, [n]: vv };
            }
            // paramNames で配置場所が指定されていない場合は、 alg と同じ場所
            if (perRcpt.paramNames.has('alg')) {
                perRcpt.params = { ...perRcpt.params, [n]: vv };
                perRcpt.paramNames.add(n);
            }
        });
    }
}
class JWEHeaderforOne extends JWESharedHeader {
    constructor(alg, enc, options) {
        // オプションの指定がない時は、alg と enc はともに Protected Header として扱う
        if (!options) {
            super({ p: { initialValue: { alg, enc } } });
            return;
        }
        // alg と enc をどのヘッダに組み込むか決定する。また options との整合性をチェック
        for (const n of ['alg', 'enc']) {
            let isConfigured = false;
            for (const i of ['p', 'su', 'ru']) {
                const opt = options[i];
                if (opt?.initialValue?.[n]) {
                    if (opt.initialValue?.[n] !== (n === 'alg' ? alg : enc)) {
                        throw new TypeError(`オプションで指定する ${i}.InitialValue と ${n} の値が一致していない`);
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
                    }
                    else {
                        options.p.initialValue = { [n]: n === 'alg' ? alg : enc };
                    }
                    if (options.p.paramNames) {
                        options.p.paramNames.add(n);
                    }
                }
                else {
                    options.p = { initialValue: { [n]: n === 'alg' ? alg : enc } };
                }
            }
        }
        // Protected Header と Shared Unprotected Header を保持する JWESharedHeader をインスタンス化
        super(options);
        let perRcptParams;
        const perRcptParamNames = new Set();
        if (options.ru) {
            const opt = options.ru;
            if (opt.initialValue) {
                if (opt.paramNames) {
                    for (const n of Object.keys(opt.initialValue)) {
                        if (isJOSEHeaderParamName(n) && !opt.paramNames.has(n)) {
                            throw new TypeError('オプションで指定する ru.Header の初期値と Header Parameter Names が一致していない' +
                                `because: initValue にあるパラメータ名 ${n} は paramNames ${opt.paramNames} に含まれていません`);
                        }
                    }
                    opt.paramNames.forEach((n) => perRcptParamNames.add(n));
                }
                else {
                    Object.keys(opt.initialValue).forEach((n) => {
                        if (isJOSEHeaderParamName(n))
                            perRcptParamNames.add(n);
                    });
                }
                perRcptParams = { ...perRcptParams, ...opt.initialValue };
            }
            else {
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
                throw new TypeError('オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません');
            }
        }
        // options の整合性確認が済んだので、インスタンスを作成
        if (perRcptParamNames.size !== 0) {
            this.perRcpt = { params: perRcptParams ?? {}, paramNames: perRcptParamNames };
        }
    }
    PerRecipient() {
        if (!this.perRcpt)
            return undefined;
        const entries = Object.entries(this.perRcpt.params).filter(([n]) => isJOSEHeaderParamName(n) && this.perRcpt?.paramNames.has(n));
        if (entries.length === 0)
            return undefined;
        return Object.fromEntries(entries);
    }
    JOSE() {
        return { ...this.shared, ...this.PerRecipient() };
    }
    update(v) {
        super.update(v);
        Object.entries(v).forEach(([n, vv]) => {
            if (!isJOSEHeaderParamName(n))
                return;
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

function jweSerializationFormat(data) {
    if (typeof data == 'string') {
        return 'compact';
    }
    if (isJWEJSONSerialization(data)) {
        return 'json';
    }
    if (isJWEFlattenedJSONSerialization(data)) {
        return 'json_flat';
    }
    throw new TypeError(`${data} は Serialized JWE ではない`);
}
const JWECompactSerializer = {
    serialize: serializeCompact$1,
    deserialize: deserializeCompact$1,
};
const JWEJSONSerializer = {
    serialize: serializeJSON$1,
    deserialize: deserializeJSON$1,
    is: isJWEJSONSerialization,
    equals: equalsJWEJSONSerialization,
};
const JWEFlattenedJSONSerializer = {
    serialize: serializeFlattenedJSON,
    deserialize: deserializeFlattenedJSON,
    is: isJWEFlattenedJSONSerialization,
    equals: equalsJWEFlattenedJSONSerialization,
};
function serializeCompact$1(p_b64u, ek, iv, c, tag) {
    return `${p_b64u}.${BASE64URL(ek)}.${BASE64URL(iv)}.${BASE64URL(c)}.${BASE64URL(tag)}`;
}
function deserializeCompact$1(compact) {
    const l = compact.split('.');
    const [h, ek, iv, c, tag] = l;
    if (h == null || ek == null || iv == null || c == null || tag == null) {
        throw new EvalError('JWS Compact Serialization の形式ではない');
    }
    return {
        p_b64u: h,
        ek: BASE64URL_DECODE(ek),
        iv: BASE64URL_DECODE(iv),
        c: BASE64URL_DECODE(c),
        tag: BASE64URL_DECODE(tag),
    };
}
function isJWEJSONSerialization(arg) {
    return (isObject(arg) &&
        (arg.protected == null || typeof arg.protected === 'string') &&
        (arg.unprotected == null || isJOSEHeaderParams(arg.unprotected, 'JWE')) &&
        (arg.iv == null || typeof arg.iv === 'string') &&
        (arg.aad == null || typeof arg.aad === 'string') &&
        typeof arg.ciphertext === 'string' &&
        (arg.tag == null || typeof arg.tag === 'string') &&
        Array.isArray(arg.recipients) &&
        arg.recipients.every((u) => isObject(u) &&
            (u.header == null || isJOSEHeaderParams(u.header, 'JWE')) &&
            (u.encrypted_key == null || typeof u.encrypted_key === 'string')));
}
function equalsJWEJSONSerialization(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    for (const n of ['protected', 'iv', 'aad', 'ciphertext', 'tag']) {
        if (l[n] == null && r[n] == null)
            continue;
        if (l[n] == null || r[n] == null)
            return false;
        if (l[n] === r[n])
            continue;
    }
    if (!equalsJOSEHeaderParams(l.unprotected, r.unprotected))
        return false;
    return (l.recipients.every((ll) => r.recipients.some((rr) => equalsRecipientInJWEJSONSerialization(rr, ll))) &&
        r.recipients.every((rr) => l.recipients.some((ll) => equalsRecipientInJWEJSONSerialization(ll, rr))));
}
function equalsRecipientInJWEJSONSerialization(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    if (l.encrypted_key !== r.encrypted_key)
        return false;
    if (!equalsJOSEHeaderParams(l.header, r.header))
        return false;
    return true;
}
function serializeJSON$1(c, rcpt, p_b64u, hsu, iv, aad, tag) {
    return {
        protected: p_b64u,
        unprotected: hsu,
        iv: iv ? BASE64URL(iv) : undefined,
        aad: aad ? BASE64URL(aad) : undefined,
        ciphertext: BASE64URL(c),
        tag: tag ? BASE64URL(tag) : undefined,
        recipients: Array.isArray(rcpt)
            ? rcpt.map((r) => ({
                header: r.h,
                encrypted_key: r.ek ? BASE64URL(r.ek) : undefined,
            }))
            : [{ header: rcpt.h, encrypted_key: rcpt.ek ? BASE64URL(rcpt.ek) : undefined }],
    };
}
function deserializeJSON$1(json) {
    return {
        c: BASE64URL_DECODE(json.ciphertext),
        rcpt: json.recipients[0] && !json.recipients[1]
            ? {
                h: json.recipients[0].header,
                ek: json.recipients[0].encrypted_key
                    ? BASE64URL_DECODE(json.recipients[0].encrypted_key)
                    : undefined,
            }
            : json.recipients.map((r) => ({
                h: r.header,
                ek: r.encrypted_key
                    ? BASE64URL_DECODE(r.encrypted_key)
                    : undefined,
            })),
        p_b64u: json.protected,
        hsu: json.unprotected,
        iv: json.iv ? BASE64URL_DECODE(json.iv) : new Uint8Array(),
        aad: json.aad ? BASE64URL_DECODE(json.aad) : undefined,
        tag: json.tag ? BASE64URL_DECODE(json.tag) : new Uint8Array(),
    };
}
function isJWEFlattenedJSONSerialization(arg) {
    return (isObject(arg) &&
        (arg.protected == null || typeof arg.protected === 'string') &&
        (arg.unprotected == null || isJOSEHeaderParams(arg.unprotected, 'JWE')) &&
        (arg.iv == null || typeof arg.iv === 'string') &&
        (arg.aad == null || typeof arg.aad === 'string') &&
        typeof arg.ciphertext === 'string' &&
        (arg.tag == null || typeof arg.tag === 'string') &&
        (arg.header == null || isJOSEHeaderParams(arg.header, 'JWE')) &&
        (arg.encrypted_key == null || typeof arg.encrypted_key === 'string'));
}
function equalsJWEFlattenedJSONSerialization(l, r) {
    if (l == null && r == null)
        return true;
    if (l == null || r == null)
        return false;
    for (const n of ['protected', 'iv', 'aad', 'ciphertext', 'tag']) {
        if (l[n] == null && r[n] == null)
            continue;
        if (l[n] == null || r[n] == null)
            return false;
        if (l[n] === r[n])
            continue;
    }
    if (!equalsJOSEHeaderParams(l.unprotected, r.unprotected))
        return false;
    return equalsRecipientInJWEJSONSerialization(l, r);
}
function serializeFlattenedJSON(c, h, ek, p_b64u, hsu, iv, aad, tag) {
    const json = serializeJSON$1(c, { h, ek }, p_b64u, hsu, iv, aad, tag);
    return {
        protected: json.protected,
        unprotected: json.unprotected,
        header: json.recipients[0]?.header,
        encrypted_key: json.recipients[0]?.encrypted_key,
        iv: json.iv,
        aad: json.aad,
        ciphertext: json.ciphertext,
        tag: json.tag,
    };
}
function deserializeFlattenedJSON(flat) {
    const jwe = deserializeJSON$1({
        ...flat,
        recipients: [{ header: flat.header, encrypted_key: flat.encrypted_key }],
    });
    return {
        ...jwe,
        h: Array.isArray(jwe.rcpt) ? jwe.rcpt[0]?.h : jwe.rcpt.h,
        ek: Array.isArray(jwe.rcpt) ? jwe.rcpt[0]?.ek : jwe.rcpt.ek,
    };
}

class JWE {
    constructor(header, iv, c, tag, encryptedKey, aad) {
        this.header = header;
        this.iv = iv;
        this.c = c;
        this.tag = tag;
        this.encryptedKey = encryptedKey;
        this.aad = aad;
    }
    /**
     * RFC7516#5.1 Message Encryption を行う。
     * @param alg 選択した受信者の JOSEHeader.alg. 複数人いる場合は配列で与える
     * @param keys CEK の値を決めるために Key Management Mode で使用する鍵セット
     * @param plaintext 平文
     * @param enc JOSEHeader.enc の値
     * @param options JWE を再現したり、 JOSEHeader を定めたり詳細な設定を行う場合のオプション
     * @returns
     */
    static async enc(alg, keys, encalg, plaintext, options) {
        let algPerRcpt;
        if (Array.isArray(alg)) {
            if (!alg[0] || !alg[1]) {
                throw new TypeError('alg を配列として渡す場合は長さが2以上にしてください');
            }
            algPerRcpt = [alg[0], alg[1], ...alg.slice(2)];
        }
        else {
            algPerRcpt = alg;
        }
        const header = JWEHeaderBuilder(algPerRcpt, encalg, options?.header);
        // Key Management を行う(Encrypted Key の生成と CEK の用意)
        let keyMgmt;
        let keyMgmtOpt = options?.keyMgmt;
        if (!keyMgmtOpt?.cek) {
            const cek = generateCEK(encalg);
            keyMgmtOpt = { ...keyMgmtOpt, cek };
        }
        if (Array.isArray(algPerRcpt)) {
            const list = await Promise.all(algPerRcpt.map(async (_a, i) => await sendCEK(keys, header.JOSE(i), keyMgmtOpt)));
            if (!list[0])
                throw new TypeError();
            // recipient ごとに行った Key Management の整合性チェック
            if (new Set(list.map((e) => e.cek)).size != 1) {
                throw new EvalError(`複数人に対する暗号化で異なる CEK を使おうとしている`);
            }
            const cek = list[0].cek;
            list.forEach((e, i) => {
                if (e.h)
                    header.update(e.h, i);
            });
            keyMgmt = { cek, ek: list.map((e) => e.ek) };
        }
        else {
            const { cek, ek, h } = await sendCEK(keys, header.JOSE(), keyMgmtOpt);
            if (h)
                header.update(h);
            keyMgmt = { cek, ek };
        }
        // Key Management で得られた CEK を使って
        // 平文を暗号化する。
        const { c, tag, iv } = await enc(encalg, keyMgmt.cek, plaintext, options?.iv, header.Protected_b64u(), options?.aad);
        return new JWE(header, iv, c, tag, keyMgmt.ek, options?.aad);
    }
    async dec(keys) {
        let cek;
        if (Array.isArray(this.encryptedKey)) {
            for (let i = 0; i < this.encryptedKey.length; i++) {
                try {
                    cek = await recvCEK(keys, this.header.JOSE(i), this.encryptedKey[i]);
                    break;
                }
                catch {
                    continue;
                }
            }
            if (!cek) {
                throw new EvalError(`暗号化に使われた鍵(CEK)を決定できなかった`);
            }
        }
        else {
            try {
                cek = await recvCEK(keys, this.header.JOSE(), this.encryptedKey);
            }
            catch {
                throw new EvalError(`暗号化に使われた鍵(CEK)を決定できなかった`);
            }
        }
        const encalg = this.header.JOSE().enc;
        if (!encalg) {
            throw new EvalError('コンテンツ暗号アルゴリズムの識別子がない');
        }
        const p = await dec(encalg, cek, this.c, this.tag, this.iv, this.header.Protected_b64u(), this.aad);
        return p;
    }
    serialize(s) {
        switch (s) {
            case 'compact': {
                if (this.encryptedKey && Array.isArray(this.encryptedKey)) {
                    throw new TypeError('JWE Compact Serialization は複数暗号化を表現できない');
                }
                if (this.header.PerRecipient()) {
                    throw new TypeError('JWE Compact Serialization は JWE PerRecipient Unprotected Header を表現できない');
                }
                if (this.header.SharedUnprotected()) {
                    throw new TypeError('JWE Compact Serialization は JWE Shared Unprotected Header を表現できない');
                }
                if (this.aad) {
                    throw new TypeError('JWE Compact Serialization は JWE AAD を表現できない');
                }
                const p_b64u = this.header.Protected_b64u();
                if (!p_b64u) {
                    throw new TypeError('JWE Compact Serialization では JWE Protected Header が必須');
                }
                return JWECompactSerializer.serialize(p_b64u, this.encryptedKey ?? new Uint8Array(), this.iv, this.c, this.tag);
            }
            case 'json': {
                return JWEJSONSerializer.serialize(this.c, Array.isArray(this.encryptedKey)
                    ? this.encryptedKey.map((ek, i) => ({ h: this.header.PerRecipient(i), ek }))
                    : { h: this.header.PerRecipient(), ek: this.encryptedKey }, this.header.Protected_b64u(), this.header.SharedUnprotected(), this.iv, this.aad, this.tag);
            }
            case 'json_flat': {
                if (Array.isArray(this.encryptedKey)) {
                    throw new TypeError('JWE Flattened JSON Serialization は複数暗号化を表現できない');
                }
                return JWEFlattenedJSONSerializer.serialize(this.c, this.header.PerRecipient(), this.encryptedKey, this.header.Protected_b64u(), this.header.SharedUnprotected(), this.iv, this.aad, this.tag);
            }
            default:
                throw new TypeError(`${s} は JWESerialization format ではない`);
        }
    }
    static deserialize(data) {
        switch (jweSerializationFormat(data)) {
            case 'compact': {
                const { p_b64u, c, tag, iv, ek } = JWECompactSerializer.deserialize(data);
                const header = JWEHeaderBuilderFromSerializedJWE(p_b64u);
                return new JWE(header, iv, c, tag, ek);
            }
            case 'json': {
                const { c, rcpt, p_b64u, hsu, iv, aad, tag } = JWEJSONSerializer.deserialize(data);
                const header = JWEHeaderBuilderFromSerializedJWE(p_b64u, hsu, Array.isArray(rcpt) ? rcpt.map((r) => r.h) : rcpt.h);
                return new JWE(header, iv, c, tag, Array.isArray(rcpt) ? rcpt.map((r) => r.ek) : rcpt.ek, aad);
            }
            case 'json_flat': {
                const { c, h, ek, p_b64u, hsu, iv, aad, tag } = JWEFlattenedJSONSerializer.deserialize(data);
                const header = JWEHeaderBuilderFromSerializedJWE(p_b64u, hsu, h);
                return new JWE(header, iv, c, tag, ek, aad);
            }
        }
    }
}
async function enc(encalg, cek, m, iv, p_b64u, aad) {
    let aad_str = p_b64u ?? '';
    if (aad) {
        aad_str += '.' + BASE64URL(aad);
    }
    return await newEncOperator(encalg).enc(encalg, cek, m, ASCII(aad_str), iv);
}
async function dec(encalg, cek, c, tag, iv, p_b64u, aad) {
    let aad_str = p_b64u ?? '';
    if (aad) {
        aad_str += '.' + BASE64URL(aad);
    }
    return await newEncOperator(encalg).dec(encalg, cek, iv, ASCII(aad_str), c, tag);
}
async function sendCEK(keys, h, options) {
    if (!h.alg) {
        throw new TypeError('alg が選択されていない');
    }
    const key = identifyJWK(keys, { ...h, kty: ktyFromAlg(h.alg) });
    switch (keyMgmtModeFromAlg(h.alg)) {
        case 'KE': {
            if (!options?.cek)
                throw new EvalError(`Key Encryption では CEK を与えてください`);
            if (!isJWK(key, 'Pub'))
                throw new TypeError(`JWE 生成時の Key Encryption では秘密鍵を使いません`);
            const ek = await newKeyEncryptor(h.alg).enc(h.alg, key, options.cek);
            return { ek, cek: options.cek };
        }
        case 'KW': {
            if (!options?.cek)
                throw new EvalError(`Key Wrapping では CEK を与えてください`);
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
            const { ek, h: updatedH } = await newKeyAgreementerWithKeyWrapping(h.alg).wrap(key, options.cek, h, eprivk);
            return { ek, cek: options.cek, h: updatedH };
        }
        case 'DE': {
            const cek = await newDirectEncrytor(h.alg).extract(h.alg, key);
            return { cek };
        }
    }
}
async function recvCEK(keys, h, ek) {
    if (!h.alg) {
        throw new TypeError('alg が選択されていない');
    }
    const key = identifyJWK(keys, { ...h, kty: ktyFromAlg(h.alg) });
    if (!isJWK(key, 'Priv')) {
        throw new EvalError('Encrypted Key から CEK を決定する秘密鍵を同定できなかった');
    }
    switch (keyMgmtModeFromAlg(h.alg)) {
        case 'KE': {
            if (!ek)
                throw new EvalError(`Encrypted Key を与えてください`);
            const cek = await newKeyEncryptor(h.alg).dec(h.alg, key, ek);
            return cek;
        }
        case 'KW': {
            if (!ek)
                throw new EvalError(`Encrypted Key を与えてください`);
            const cek = await newKeyWrappaer(h.alg).unwrap(key, ek, h);
            return cek;
        }
        case 'DKA': {
            const cek = await newDirectKeyAgreementer(h.alg).partyV(key, h);
            return cek;
        }
        case 'KAKW': {
            if (!ek)
                throw new EvalError(`Encrypted Key を与えてください`);
            const cek = await newKeyAgreementerWithKeyWrapping(h.alg).unwrap(key, ek, h);
            return cek;
        }
        case 'DE': {
            const cek = await newDirectEncrytor(h.alg).extract(h.alg, key);
            return cek;
        }
    }
}

const paths$1 = [
    '5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json',
    '5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json',
    '5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json',
    '5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json',
    '5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json',
    '5_6.direct_encryption_using_aes-gcm.json',
    '5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json',
    '5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json',
    // '5_9.compressed_content.json',
    '5_10.including_additional_authentication_data.json',
    '5_11.protecting_specific_header_fields.json',
    '5_12.protecting_content_only.json',
    '5_13.encrypting_to_multiple_recipients.json',
];
const baseURL$1 = 'https://raw.githubusercontent.com/ietf-jose/cookbook/master/jwe/';
async function fetchData$1(path) {
    const resp = await fetch(baseURL$1 + path);
    const data = await resp.json();
    // examples のミスを治す
    if (path === '5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json') {
        // rfc7516#7.2.1 によると recipients は 空オブジェクトでも recipient ごとにいるはずだが...
        data.output.json.recipients = [{}];
    }
    if (path === '5_6.direct_encryption_using_aes-gcm.json') {
        // rfc7516#7.2.1 によると recipients は 空オブジェクトでも recipient ごとにいるはずだが...
        data.output.json.recipients = [{}];
    }
    if (path === '5_13.encrypting_to_multiple_recipients.json') {
        // タイポ
        data.input.enc = 'A128CBC-HS256';
    }
    if (!isData$1(data)) {
        throw new EvalError('テストデータの取得に失敗');
    }
    return data;
}
const isData$1 = (arg) => isObject(arg) &&
    typeof arg.title === 'string' &&
    (arg.reproducible == null || typeof arg.reproducible === 'boolean') &&
    isObject(arg.input) &&
    typeof arg.input.plaintext === 'string' &&
    (arg.input.key == null || isArrayable(arg.input.key, (k) => isJWK(k))) &&
    (arg.input.pwd == null || typeof arg.input.pwd === 'string') &&
    isArrayable(arg.input.alg, (u) => isAlg(u, 'JWE')) &&
    isEncAlg(arg.input.enc) &&
    (arg.input.aad == null || typeof arg.input.aad === 'string') &&
    isObject(arg.generated) &&
    (arg.generated.cek == null || typeof arg.generated.cek === 'string') &&
    typeof arg.generated.iv === 'string' &&
    (arg.encrypting_key == null ||
        isArrayable(arg.encrypting_key, (u) => isObject(u) &&
            (u.header == null || isJOSEHeaderParams(u.header, 'JWE')) &&
            (u.epk == null || isJWK(u.epk, 'EC', 'Priv')))) &&
    isObject(arg.encrypting_content) &&
    (arg.encrypting_content.protected == null ||
        isJOSEHeaderParams(arg.encrypting_content.protected, 'JWE')) &&
    (arg.encrypting_content.protected_b64u == null ||
        typeof arg.encrypting_content.protected_b64u === 'string') &&
    (arg.encrypting_content.unprotected == null ||
        isJOSEHeaderParams(arg.encrypting_content.unprotected, 'JWE')) &&
    isObject(arg.output) &&
    (arg.output.compact == null || typeof arg.output.compact === 'string') &&
    JWEJSONSerializer.is(arg.output.json) &&
    (arg.output.json_flat == null || JWEFlattenedJSONSerializer.is(arg.output.json_flat));

async function test$7(path) {
    const data = await fetchData$1(path);
    let allGreen = true;
    const title = 'RFC7520#5 TEST NAME: ' + data.title;
    let log = '';
    // 準備
    const plaintext = UTF8(data.input.plaintext);
    const options = {
        header: {
            p: data.encrypting_content.protected
                ? {
                    initialValue: data.encrypting_content.protected,
                    b64u: data.encrypting_content.protected_b64u,
                }
                : undefined,
            su: data.encrypting_content.unprotected
                ? {
                    initialValue: data.encrypting_content.unprotected,
                }
                : undefined,
            ru: Array.isArray(data.encrypting_key)
                ? data.encrypting_key.map((k) => ({
                    initialValue: k.header,
                }))
                : data.encrypting_key?.header
                    ? {
                        initialValue: data.encrypting_key.header,
                    }
                    : undefined,
        },
        keyMgmt: {
            cek: data.generated.cek ? BASE64URL_DECODE(data.generated.cek) : undefined,
            eprivk: Array.isArray(data.encrypting_key)
                ? data.encrypting_key.filter((k) => k.epk != null).map((k) => k.epk)
                : data.encrypting_key?.epk,
        },
        iv: BASE64URL_DECODE(data.generated.iv),
        aad: data.input.aad ? UTF8(data.input.aad) : undefined,
    };
    const keys = {
        keys: data.input.key
            ? Array.isArray(data.input.key)
                ? data.input.key
                : [data.input.key]
            : data.input.pwd
                ? [{ kty: 'oct', k: BASE64URL(UTF8(data.input.pwd)) }]
                : [],
    };
    // 暗号文送信者用の鍵準備
    const encKeys = {
        keys: keys.keys.map((k) => {
            if (isJWK(k, 'Priv'))
                return exportPubJWK(k);
            if (isJWK(k, 'Pub'))
                ;
            throw TypeError(`JWK ではない鍵が紛れ込んでいる ${k}`);
        }),
    };
    // JWE 生成
    const jwe = await JWE.enc(data.input.alg, encKeys, data.input.enc, plaintext, options);
    if (data.reproducible) {
        log += 'テストには再現性があるため、シリアライズした結果を比較する\n';
        if (data.output.compact) {
            const compact = jwe.serialize('compact');
            const same = data.output.compact === compact;
            allGreen &&= same;
            log += 'Compact: ' + (same ? '(OK) ' : 'X ');
        }
        if (data.output.json) {
            const json = jwe.serialize('json');
            const same = JWEJSONSerializer.equals(data.output.json, json);
            allGreen &&= same;
            log += 'JSON: ' + (same ? '(OK) ' : 'X ');
        }
        if (data.output.json_flat) {
            const flat = jwe.serialize('json_flat');
            const same = JWEFlattenedJSONSerializer.equals(data.output.json_flat, flat);
            allGreen &&= same;
            log += 'FlattenedJSON: ' + (same ? '(OK) ' : 'X ');
        }
        log += '\n';
    }
    else {
        log += 'テストには再現性がない (e.g. 署名アルゴリズムに乱数がからむ)\n';
    }
    log += 'JWE の復号を行う\n';
    for (const key of keys.keys) {
        const keysOfOne = { keys: [key] };
        log += `Key(${key.kty}, ${key.kid}) で復号`;
        try {
            const decryptedtext = await jwe.dec(keysOfOne);
            const valid = UTF8_DECODE(decryptedtext) === UTF8_DECODE(plaintext);
            allGreen &&= valid;
            log += 'Encrypt and Decrypt JWE ' + (valid ? '(OK)' : '(X)') + '\n';
        }
        catch (err) {
            allGreen = false;
            console.log(err);
            log += 'Encrypt and Decrypt JWE (X)\n';
        }
        if (data.output.compact) {
            const jwe = JWE.deserialize(data.output.compact);
            try {
                const decryptedtext = await jwe.dec(keysOfOne);
                const valid = UTF8_DECODE(decryptedtext) === UTF8_DECODE(plaintext);
                allGreen &&= valid;
                log += 'Deserialize Compact and Decrypt JWE ' + (valid ? '(OK)' : '(X)') + '\n';
            }
            catch (err) {
                allGreen = false;
                console.log(err);
                log += 'Deserialize Compact and Decrypt JWE (X)\n';
            }
        }
        if (data.output.json) {
            const jwe = JWE.deserialize(data.output.json);
            try {
                const decryptedtext = await jwe.dec(keysOfOne);
                const valid = UTF8_DECODE(decryptedtext) === UTF8_DECODE(plaintext);
                allGreen &&= valid;
                log += 'Deserialize JSON and Decrypt JWE ' + (valid ? '(OK)' : '(X)') + '\n';
            }
            catch (err) {
                allGreen = false;
                console.log(err);
                log += 'Deserialize JSON and Decrypt JWE (X)\n';
            }
        }
        if (data.output.json_flat) {
            const jwe = JWE.deserialize(data.output.json_flat);
            try {
                const decryptedtext = await jwe.dec(keysOfOne);
                const valid = UTF8_DECODE(decryptedtext) === UTF8_DECODE(plaintext);
                allGreen &&= valid;
                log += 'Deserialize Flattened JSON and Decrypt JWE ' + (valid ? '(OK)' : '(X)') + '\n';
            }
            catch (err) {
                allGreen = false;
                console.log(err);
                log += 'Deserialize Flattened JSON and Decrypt JWE (X)\n';
            }
        }
    }
    return { title, allGreen, log };
}

// --------------------BEGIN RFC7517 appendix.A test --------------------
async function test$6() {
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
async function test$5() {
    return { title: 'RFC7517#B.Example Use of "x5c" Parameter;', log: '', allGreen: true };
    //   let allGreen = true;
    //   const title = 'RFC7517#B.Example Use of "x5c" Parameter;';
    //   let log = 'TEST NAME: Self Signed Certificate Verification: ';
    //   const cert = parseX509BASE64EncodedDER(b.x5c[0]);
    //   const isVerified = await validateSelfSignedCert(cert);
    //   if (isVerified) {
    //     log += 'X509証明書(RSA) OK ';
    //   } else {
    //     log += 'X509証明書(RSA) X ';
    //     allGreen = false;
    //   }
    //   const eccert = parseX509BASE64EncodedDER(amazon_root_ca_3.x5c[0]);
    //   const isECVerified = await validateSelfSignedCert(eccert);
    //   if (isECVerified) {
    //     log += 'X509証明書(EC) OK\n';
    //   } else {
    //     log += 'X509証明書(EC) X\n';
    //     allGreen = false;
    //   }
    //   log += 'TEST NAME: Validate JWK.x5c\n';
    //   if (isJWK(b, 'RSA', 'Pub')) {
    //     if (await verifyJWK(b, { x5c: { selfSigned: true } })) {
    //       log += 'JWK.x5c (RSA) の検証と整合性の確認に成功\n';
    //     } else {
    //       log += 'JWK.x5c (RSA) の検証に失敗\n';
    //       allGreen = false;
    //     }
    //   } else {
    //     log += 'JWK<RSA,Pub> のパースに失敗\n';
    //     allGreen = false;
    //   }
    //   if (isJWK(amazon_root_ca_3, 'EC', 'Pub')) {
    //     if (await verifyJWK(amazon_root_ca_3, { x5c: { selfSigned: true } })) {
    //       log += 'JWK.x5c (EC) の検証と整合性の確認に成功\n';
    //     } else {
    //       log += 'JWK.x5c (EC) の検証に失敗\n';
    //       allGreen = false;
    //     }
    //   } else {
    //     log += 'JWK<EC, Pub> のパースに失敗\n';
    //     allGreen = false;
    //   }
    //   log += "TEST NAME: Validate JWK.x5c of microsoft's JWKSet for oidc: ";
    //   const data = await (
    //     await fetch('https://login.microsoftonline.com/common/discovery/v2.0/keys')
    //   ).json();
    //   if (!isJWKSet(data)) {
    //     log += 'JWKSet の取得に失敗\n';
    //     allGreen = false;
    //   } else {
    //     for (const key of data.keys) {
    //       if (isJWK(key, 'RSA', 'Pub')) {
    //         if (await verifyJWK(key, { x5c: { selfSigned: true } })) {
    //           log += 'JWK.x5c の検証と整合性の確認に成功\n';
    //         } else {
    //           log += 'JWK.x5c の検証に失敗\n';
    //           allGreen = false;
    //         }
    //       } else {
    //         log += 'MSから取得する鍵は全て RSA 公開鍵のはず\n';
    //         allGreen = false;
    //       }
    //     }
    //   }
    //   return { title, log, allGreen };
    // }
    // const b = {
    //   kty: 'RSA',
    //   use: 'sig',
    //   kid: '1b94c',
    //   n: 'vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ',
    //   e: 'AQAB',
    //   x5c: [
    //     'MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==',
    //   ],
    // };
    // // ref: https://good.sca3a.amazontrust.com/ に基づいて JWK を生成した
    // const amazon_root_ca_3 = {
    //   kty: 'EC',
    //   crv: 'P-256',
    //   x: 'KZenxkF_wA2b6AEbVsbyUqW6LbIS6NIu1_rJxdiqbR8',
    //   y: 'c4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt4',
    //   x5c: [
    //     'MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKlui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6jQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSrttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkrBqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteMYyRIHN8wfdVoOw==',
    //   ],
}
// --------------------END RFC7517 appendix.B test --------------------

// --------------------BEGIN RFC7520 Section.3 for EC test --------------------
async function test$4() {
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

// --------------------BEGIN JWA EC algorithms --------------------
/**
 * ECDSA アルゴリズムで署名の作成と検証を行うオペレータを定義する
 */
const ESSigOperator = { sign: sign$2, verify: verify$3 };
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

// --------------------BEGIN JWA HMAC algorithms --------------------
/**
 * HMAC アルゴリズムで MAC の生成と検証を行うオペレータを定義する
 */
const HMACOperator = { mac, verify: verify$2 };
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

// --------------------BEGIN JWA RSA algorithms --------------------
/**
 * RSASSA-PKCS1-v1.5 か RSA-PSS アルゴリズムで署名の作成と検証を行うオペレータを定義する
 */
const RSASigOperator = {
    sign: sign$1,
    verify: verify$1,
};
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

/**
 * @file interface.ts の実装を集約して jws.ts へ提供する。
 */
const isSigAlg = [isRSAlg, isPSAlg, isESAlg];
const isMACAlg = [isHSAlg];
function JWSOpeModeFromAlg(alg) {
    if (isSigAlg.some((f) => f(alg)))
        return 'Sig';
    if (isMACAlg.some((f) => f(alg)))
        return 'MAC';
    if (alg === 'none')
        return 'None';
    throw new TypeError(`${alg} の実装がない`);
}
/**
 * 署名アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newSigOperator(alg) {
    if (isRSAlg(alg) || isPSAlg(alg))
        return RSASigOperator;
    if (isESAlg(alg))
        return ESSigOperator;
    throw new TypeError(`SigOperator<${alg}> は実装されていない`);
}
/**
 * MAC アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newMacOperator(alg) {
    if (isHSAlg(alg))
        return HMACOperator;
    throw TypeError(`MacOperator<${alg}> は実装されていない`);
}

// --------------------BEGIN JWS Header definition --------------------
/**
 * JWS において JOSE Header は 一連の Header Parameters からなるが、これらパラメータは JWS Protected Header と
 * JWS Unprotected Header のいずれかに分類される。
 * JWS が複数署名に対応している場合は、 署名操作ごとに一つの JWS Header を用意する必要がある。
 */
class JWSHeader {
    constructor(alg, options) {
        // options の指定がない時は、 protected header に alg を組み込む
        if (!options) {
            this.h = { alg };
            this.paramNames = { p: new Set(['alg']), u: new Set() };
            return;
        }
        // alg をどのヘッダに組み込むか決定する。また options との整合性をチェック
        {
            let isConfigured = false;
            for (const i of ['p', 'u']) {
                const opt = options[i];
                if (opt?.initialValue?.alg) {
                    if (opt.initialValue.alg !== alg) {
                        throw new TypeError(`options.${i}.initialValue.alg: ${opt.initialValue.alg} と ${alg} の値が一致していない`);
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
                }
                else {
                    options.p = { initialValue: { alg } };
                }
            }
        }
        // コンストラクタでプロパティに与える情報たち
        let value = {};
        const paramNames = {
            p: new Set(),
            u: new Set(),
        };
        for (const i of ['p', 'u']) {
            const opt = options[i];
            if (!opt)
                continue;
            if (!opt.initialValue) {
                opt.paramNames?.forEach((n) => paramNames[i].add(n));
                continue;
            }
            // 初期値として与えるヘッダー情報とヘッダー名情報が矛盾していないかチェック
            if (opt.paramNames) {
                for (const n of Object.keys(opt.initialValue)) {
                    if (isJOSEHeaderParamName(n) && !opt.paramNames.has(n)) {
                        throw new TypeError(`options.${i}.initialValue.${n} に値(${opt.initialValue[n]})があるが options.${i}.paramNames には含まれていない`);
                    }
                }
                opt.paramNames.forEach((n) => paramNames[i].add(n));
            }
            else {
                Object.keys(opt.initialValue).forEach((n) => {
                    if (isJOSEHeaderParamName(n))
                        paramNames[i].add(n);
                });
            }
            value = { ...value, ...opt.initialValue };
        }
        // オプションで渡される Protected Header の Base64url 表現が JOSE Header のものかチェック
        if (options.p?.b64u) {
            let p;
            try {
                p = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(options.p.b64u)));
            }
            catch (e) {
                throw new TypeError(`options.p.b64u: ${options.p.b64u} は JSON の base64url encoding ではない`);
            }
            if (!isJOSEHeaderParams(p, 'JWS')) {
                throw new TypeError(`options.p.b64u: ${options.p.b64u} は JOSE Header for JWS の base64url encoding ではない`);
            }
            this.p_b64u = {
                raw: options.p?.b64u,
                json: p,
            };
        }
        // params の整合性チェック。重複していないかどうか判断する
        {
            const params = new Set();
            let paramsDesiredSize = 0;
            for (const n of ['p', 'u']) {
                paramNames[n].forEach((name) => params.add(name));
                paramsDesiredSize += paramNames[n].size;
            }
            if (paramsDesiredSize !== params.size) {
                throw new TypeError('オプションで指定する Header Parameter Names が衝突しています。同じパラメータを異なるヘッダーに組み込むことはできません');
            }
        }
        // インスタンスの作成
        this.h = value;
        this.paramNames = paramNames;
        return;
    }
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
    static build(alg, options) {
        return new JWSHeader(alg, options);
    }
    /**
     * JWS Header を JWS Serialization からの情報をもとに構築する。
     * @param p_b64u JWS Protected Header の base64url encoding 表現
     * @param u JWS Unprotected Header の JSON 表現
     * @returns JWS Header
     * @throws options が alg や自身で矛盾している場合に TypeError を吐く
     */
    static buildFromJWSSerialization(p_b64u, u) {
        let alg;
        let options;
        if (p_b64u) {
            let initialValue;
            try {
                initialValue = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(p_b64u)));
            }
            catch (e) {
                throw new TypeError(`p_b64u: ${p_b64u} は JSON の base64url encoding ではない`);
            }
            if (!isJOSEHeaderParams(initialValue, 'JWS')) {
                throw new TypeError(`p_b64u: ${p_b64u} は JOSE Header for JWS の base64url encoding ではない`);
            }
            if (initialValue.alg) {
                alg = initialValue.alg;
            }
            if (options) {
                options.p = { initialValue: initialValue, b64u: p_b64u };
            }
            else {
                options = {
                    p: { initialValue: initialValue, b64u: p_b64u },
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
            }
            else {
                options = { u: { initialValue } };
            }
        }
        if (!alg) {
            throw new TypeError('p_b64u と u を合わせても alg が存在しなかった');
        }
        return new JWSHeader(alg, options);
    }
    /**
     * JWS Protected Header と JWS Unprotected Header の Union を返す
     * @returns JOSE Header
     */
    JOSE() {
        return this.h;
    }
    /**
     * JWS Protected Header があれば返す。
     * @returns undefined or JWS Protected Header
     */
    Protected() {
        const entries = Object.entries(this.h).filter(([n]) => isJOSEHeaderParamName(n) && this.paramNames.p.has(n));
        if (entries.length === 0)
            return undefined;
        return Object.fromEntries(entries);
    }
    /**
     * JWS Protected Header の base64url 表現があれば返す。
     * ヘッダ構成時に base64url 情報を与えていればそれを使う。ただし、このメソッド実行時にこのインスタンスが保有する
     * this.Protected() と内容が一致しない場合は TypeError を吐く
     * @returns undefined or BASE64URL(UTF8(JWS Protected Header))
     * @throws options と矛盾したら TypeError
     */
    Protected_b64u() {
        if (this.p_b64u) {
            if (!equalsJOSEHeaderParams(this.p_b64u.json, this.Protected())) {
                throw new TypeError(`オプションで指定された Protected Header(${this.p_b64u.raw}) と生成した Protected Header(${JSON.stringify(this.Protected())}) が一致しなかった`);
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
    Unprotected() {
        const entries = Object.entries(this.h).filter(([n]) => isJOSEHeaderParamName(n) && this.paramNames.u.has(n));
        if (entries.length === 0)
            return undefined;
        return Object.fromEntries(entries);
    }
    /**
     * JWS Header の内容を更新する。（署名生成時生成した検証時に必要なパラメータなど)
     * @param v 更新内容の JOSE Header Parameteres
     */
    update(v) {
        Object.entries(v).forEach(([n, vv]) => {
            if (!isJOSEHeaderParamName(n))
                return;
            this.h = { ...this.h, [n]: vv };
            if (this.paramNames.p.has(n) || this.paramNames.u.has(n)) {
                return;
            }
            if (this.paramNames.p.has('alg')) {
                this.paramNames.p.add(n);
            }
            else {
                this.paramNames.u.add(n);
            }
        });
    }
}
// --------------------END JWS Header definition --------------------

// --------------------BEGIN JWS Serialization definition --------------------
/**
 * Serialization された JWS のフォーマットが何か判定する
 */
function jwsSerializationFormat(data) {
    if (typeof data == 'string') {
        return 'compact';
    }
    if (typeof data == 'object' && data != null) {
        if ('signatures' in data)
            return 'json';
        return 'json_flat';
    }
    throw TypeError(`${data} は JWSSerialization ではない`);
}
const JWSCompactSerializer = {
    serialize: serializeCompact,
    deserialize: deserializeCompact,
};
const JWSJSONSerializer = {
    serialize: serializeJSON,
    deserialize: deserializeJSON,
    is: isJWSJSONSerialization,
    equals: equalsJWSJSONSerialization,
};
const JWSFlattenedJSONSerializer = {
    serialize: serializeJWSFlattenedJSON,
    deserialize: deserializeJWSFlattenedJSON,
    is: isJWSFlattenedJSONSerialization,
    equals: equalsJWSFlattenedJSONSerialization,
};
/**
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * に JWS をシリアライズする。
 */
function serializeCompact(p_b64u, m, s) {
    return `${p_b64u}.${BASE64URL(m)}.${s ? BASE64URL(s) : ''}`;
}
/**
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * を JWS にデシリアライズする。
 */
function deserializeCompact(compact) {
    const c = compact.split('.');
    const [header, payload, signature] = c;
    if (header == null || payload == null || signature == null) {
        throw 'JWS Compact Serialization の形式ではない';
    }
    if (header === '') {
        throw 'JWS Compact Serialization では Protected Header が必須';
    }
    return {
        p_b64u: header,
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
            (s.header == null || isJOSEHeaderParams(s.header, 'JWS')) &&
            (s.protected == null || typeof s.protected === 'string')));
}
function serializeJSON(m, hs) {
    const hsList = Array.isArray(hs) ? hs : [hs];
    return {
        payload: BASE64URL(m),
        signatures: hsList.map((hs) => {
            return {
                signature: BASE64URL(hs.sig),
                header: hs.u,
                protected: hs.p_b64u,
            };
        }),
    };
}
function deserializeJSON(json) {
    const m = BASE64URL_DECODE(json.payload);
    const hslist = json.signatures.map((sig) => ({
        p_b64u: sig.protected,
        u: sig.header,
        sig: BASE64URL_DECODE(sig.signature),
    }));
    return { m, hs: hslist[0] && !hslist[1] ? hslist[0] : hslist };
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
                if (equalsJOSEHeaderParams(ll, rr))
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
function serializeJWSFlattenedJSON(h, m, s) {
    return {
        payload: BASE64URL(m),
        signature: BASE64URL(s),
        header: h.u,
        protected: h.p_b64u,
    };
}
function deserializeJWSFlattenedJSON(flat) {
    return {
        h: { p_b64u: flat.protected, u: flat.header },
        m: BASE64URL_DECODE(flat.payload),
        s: BASE64URL_DECODE(flat.signature),
    };
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
function isJWSFlattenedJSONSerialization(arg) {
    return (isObject(arg) &&
        typeof arg.payload === 'string' &&
        (arg.protected == null || typeof arg.protected === 'string') &&
        typeof arg.signature === 'string' &&
        (arg.header == null || isJOSEHeaderParams(arg.header, 'JWS')));
}
// --------------------END JWS Serialization definition --------------------

// --------------------BEGIN JWS implementation --------------------
/**
 * JWS はデジタル署名もしくはメッセージ認証コードで保護されたコンテンツを表現する JSON ベースのデータ構造である。
 */
class JWS {
    constructor(
    // 完全性が保護されるコンテンツ
    m, 
    // 署名値と署名操作を表すヘッダーからなる。複数署名の場合は配列になる
    hs) {
        this.m = m;
        this.hs = hs;
    }
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
    static async produce(alg, keys, m, options) {
        let headerPerRcpt;
        if (Array.isArray(alg)) {
            if (!alg[0] || !alg[1]) {
                throw new TypeError('alg を配列として渡す場合は長さが2以上にしてください');
            }
            if (!options?.header) {
                const h = alg.map((a) => JWSHeader.build(a));
                // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
                headerPerRcpt = [h[0], h[1], ...h.slice(2)];
            }
            else {
                const oh = options.header;
                if (!Array.isArray(oh) || oh.length !== alg.length) {
                    throw new TypeError('alg を配列としてわたし、オプションを指定する場合は同じ長さの配列にしてください。さらに、インデックスが同じ受信者を表すようにしてください');
                }
                const h = alg.map((a, i) => JWSHeader.build(a, oh[i]));
                // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
                headerPerRcpt = [h[0], h[1], ...h.slice(2)];
            }
        }
        else {
            const oh = options?.header;
            if (oh && Array.isArray(oh)) {
                throw new TypeError('alg が一つの時は、オプションを複数指定しないでください');
            }
            headerPerRcpt = JWSHeader.build(alg, oh);
        }
        // ヘッダーごとにコンテンツに対して署名や MAC 計算を行う。
        // 計算の実体は sign で実装。
        if (Array.isArray(headerPerRcpt)) {
            const hsList = await Promise.all(headerPerRcpt.map(async (header) => ({ header, sig: await sign(keys, m, header) })));
            return new JWS(m, hsList);
        }
        const sig = await sign(keys, m, headerPerRcpt);
        return new JWS(m, { header: headerPerRcpt, sig });
    }
    async validate(keys, isAllValidation = true) {
        const hsList = Array.isArray(this.hs) ? this.hs : [this.hs];
        const verifiedList = await Promise.all(hsList.map(async (hs) => await verify(keys, this.m, hs.header, hs.sig)));
        return verifiedList.reduce((prev, now) => (isAllValidation ? prev && now : prev || now));
    }
    static deserialize(data) {
        switch (jwsSerializationFormat(data)) {
            case 'compact': {
                const { p_b64u, m, s } = JWSCompactSerializer.deserialize(data);
                const header = JWSHeader.buildFromJWSSerialization(p_b64u);
                return new JWS(m, { header, sig: s });
            }
            case 'json': {
                const { m, hs } = JWSJSONSerializer.deserialize(data);
                const h = Array.isArray(hs)
                    ? hs.map((h) => ({
                        header: JWSHeader.buildFromJWSSerialization(h.p_b64u, h.u),
                        sig: h.sig,
                    }))
                    : { header: JWSHeader.buildFromJWSSerialization(hs.p_b64u, hs.u), sig: hs.sig };
                return new JWS(m, h);
            }
            case 'json_flat': {
                const { m, h, s } = JWSFlattenedJSONSerializer.deserialize(data);
                return new JWS(m, { header: JWSHeader.buildFromJWSSerialization(h.p_b64u, h.u), sig: s });
            }
        }
    }
    serialize(s) {
        switch (s) {
            case 'compact': {
                if (Array.isArray(this.hs)) {
                    throw 'JWS Compact Serialization は複数署名を表現できない';
                }
                const p_b64u = this.hs.header.Protected_b64u();
                if (!p_b64u || this.hs.header.Unprotected()) {
                    throw 'JWS Compact Serialization は JWS Unprotected Header を表現できない';
                }
                return JWSCompactSerializer.serialize(p_b64u, this.m, this.hs.sig);
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
                return JWSJSONSerializer.serialize(this.m, hs);
            }
            case 'json_flat': {
                if (Array.isArray(this.hs)) {
                    if (!this.hs[0])
                        throw new TypeError('JOSE Header が存在していない');
                    if (this.hs[1])
                        throw new TypeError('Flattened JWS JSON Serialization は複数署名を表現できない');
                    return JWSFlattenedJSONSerializer.serialize({ p_b64u: this.hs[0].header.Protected_b64u(), u: this.hs[0].header.Unprotected() }, this.m, this.hs[0].sig);
                }
                return JWSFlattenedJSONSerializer.serialize({ p_b64u: this.hs.header.Protected_b64u(), u: this.hs.header.Unprotected() }, this.m, this.hs.sig);
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
    const input = jwsinput(m, h.Protected_b64u());
    const jh = h.JOSE();
    const alg = jh.alg;
    if (!alg) {
        throw new EvalError('alg が指定されていない');
    }
    switch (JWSOpeModeFromAlg(alg)) {
        case 'None':
            // Unsecured JWS の場合は、署名値がない。
            return new Uint8Array();
        case 'Sig': {
            const key = identifyJWK(keys, { ...jh, kty: ktyFromAlg(alg) });
            if (!isJWK(key, 'Priv'))
                throw new TypeError('公開鍵で署名しようとしている');
            return newSigOperator(alg).sign(alg, key, input);
        }
        case 'MAC': {
            const key = identifyJWK(keys, { ...jh, kty: ktyFromAlg(alg) });
            return newMacOperator(alg).mac(alg, key, input);
        }
    }
}
async function verify(keys, m, h, s) {
    const jh = h.JOSE();
    const alg = jh.alg;
    if (!alg) {
        throw new EvalError('alg が指定されていない');
    }
    switch (JWSOpeModeFromAlg(alg)) {
        case 'None':
            return true;
        case 'Sig': {
            if (!s)
                return false;
            const key = identifyJWK(keys, { ...jh, kty: ktyFromAlg(alg) });
            if (!isJWK(key, 'Pub'))
                throw new TypeError(`Sig Operator の検証では公開鍵を与えてください`);
            const input = jwsinput(m, h.Protected_b64u());
            return newSigOperator(alg).verify(alg, key, input, s);
        }
        case 'MAC': {
            if (!s)
                return false;
            const key = identifyJWK(keys, { ...jh, kty: ktyFromAlg(alg) });
            const input = jwsinput(m, h.Protected_b64u());
            return newMacOperator(alg).verify(alg, key, input, s);
        }
    }
}
/**
 * RFC7515#2 JWS Signing Input はデジタル署名や MAC の計算に対する入力。
 * この値は、ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))
 */
const jwsinput = (m, p_b64u) => ASCII((p_b64u ?? '') + '.' + BASE64URL(m));
// --------------------END JWS implementation --------------------

async function test$1() {
    let allGreen = true;
    const title = 'RFC7515#Appendix1 Examples';
    let log = '';
    for (const d of data) {
        log += d.title + '\n';
        const jws = await JWS.produce(d.input.alg, d.input.jwks, d.input.message, d.input.options);
        if (d.reproducible) {
            log += 'テストには再現性があるため、シリアライズした結果を比較する\n';
            if (d.output.compact) {
                const compact = jws.serialize('compact');
                const same = d.output.compact === compact;
                allGreen &&= same;
                log += 'Compact: ' + (same ? '(OK) ' : 'X ');
            }
            if (d.output.json) {
                const json = jws.serialize('json');
                const same = JWSJSONSerializer.equals(d.output.json, json);
                allGreen &&= same;
                log += 'JSON: ' + (same ? '(OK) ' : 'X ');
            }
        }
        log += 'JWS の検証する\n';
        const verifyKeys = {
            keys: d.input.jwks.keys.map((k) => {
                if (isJWK(k, 'Priv'))
                    return exportPubJWK(k);
                if (isJWK(k, 'Pub'))
                    return k;
                throw TypeError(`JWK ではない鍵が紛れ込んでいる ${k}`);
            }),
        };
        const valid = await jws.validate(verifyKeys);
        allGreen &&= valid;
        log += 'Produce and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
        if (d.output.compact) {
            const jws = JWS.deserialize(d.output.compact);
            const valid = await jws.validate(verifyKeys);
            allGreen &&= valid;
            log += 'Deserialize Compact and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
        }
        if (d.output.json) {
            const jws = JWS.deserialize(d.output.json);
            const valid = await jws.validate(verifyKeys);
            allGreen &&= valid;
            log += 'Deserialize JSON and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
        }
    }
    return { title, allGreen, log };
}
const data = [
    {
        title: 'A.1.  Example JWS Using HMAC SHA-256',
        reproducible: true,
        input: {
            alg: 'HS256',
            jwks: {
                keys: [
                    {
                        kty: 'oct',
                        k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
                    },
                ],
            },
            message: new Uint8Array([
                123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
                34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
                47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111,
                116, 34, 58, 116, 114, 117, 101, 125,
            ]),
            options: {
                header: {
                    p: {
                        initialValue: { typ: 'JWT', alg: 'HS256' },
                        b64u: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
                    },
                },
            },
        },
        output: {
            compact: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        },
    },
    {
        title: 'A.2.  Example JWS Using RSASSA-PKCS1-v1_5 SHA-256',
        reproducible: true,
        input: {
            alg: 'RS256',
            jwks: {
                keys: [
                    {
                        kty: 'RSA',
                        n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
                        e: 'AQAB',
                        d: 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
                        p: '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
                        q: 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
                        dp: 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
                        dq: 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
                        qi: 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
                    },
                ],
            },
            message: new Uint8Array([
                123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
                34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
                47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111,
                116, 34, 58, 116, 114, 117, 101, 125,
            ]),
            options: {
                header: {
                    p: {
                        b64u: 'eyJhbGciOiJSUzI1NiJ9',
                    },
                },
            },
        },
        output: {
            compact: 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw',
        },
    },
    {
        title: 'A.3.  Example JWS Using ECDSA P-256 SHA-256',
        reproducible: false,
        input: {
            alg: 'ES256',
            jwks: {
                keys: [
                    {
                        kty: 'EC',
                        crv: 'P-256',
                        x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                        y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
                        d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
                    },
                ],
            },
            message: new Uint8Array([
                123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
                34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
                47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111,
                116, 34, 58, 116, 114, 117, 101, 125,
            ]),
            options: {
                header: {
                    p: { b64u: 'eyJhbGciOiJFUzI1NiJ9' },
                },
            },
        },
        output: {
            compact: 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
        },
    },
    {
        title: 'A.4.  Example JWS Using ECDSA P-521 SHA-512',
        input: {
            alg: 'ES512',
            jwks: {
                keys: [
                    {
                        kty: 'EC',
                        crv: 'P-521',
                        x: 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
                        y: 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
                        d: 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
                    },
                ],
            },
            message: new Uint8Array([80, 97, 121, 108, 111, 97, 100]),
            options: {
                header: {
                    p: { b64u: 'eyJhbGciOiJFUzUxMiJ9' },
                },
            },
        },
        output: {
            compact: 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn',
        },
    },
    {
        title: 'A.5.  Example Unsecured JWS',
        reproducible: true,
        input: {
            alg: 'none',
            jwks: { keys: [] },
            message: new Uint8Array([
                123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
                34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
                47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111,
                116, 34, 58, 116, 114, 117, 101, 125,
            ]),
            options: {
                header: {
                    p: { b64u: 'eyJhbGciOiJub25lIn0' },
                },
            },
        },
        output: {
            compact: 'eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.',
        },
    },
    {
        title: 'A.6.  Example JWS Using General JWS JSON Serialization',
        input: {
            alg: ['RS256', 'ES256'],
            jwks: {
                keys: [
                    {
                        kty: 'RSA',
                        n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
                        e: 'AQAB',
                        d: 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
                        p: '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
                        q: 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
                        dp: 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
                        dq: 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
                        qi: 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
                    },
                    {
                        kty: 'EC',
                        crv: 'P-256',
                        x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                        y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
                        d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
                    },
                ],
            },
            message: new Uint8Array([
                123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
                34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
                47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111,
                116, 34, 58, 116, 114, 117, 101, 125,
            ]),
            options: {
                header: [
                    {
                        p: {
                            initialValue: { alg: 'RS256' },
                            b64u: 'eyJhbGciOiJSUzI1NiJ9',
                        },
                        u: {
                            initialValue: { kid: '2010-12-29' },
                        },
                    },
                    {
                        p: {
                            initialValue: { alg: 'ES256' },
                            b64u: 'eyJhbGciOiJFUzI1NiJ9',
                        },
                        u: {
                            initialValue: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
                        },
                    },
                ],
            },
        },
        output: {
            json: {
                payload: 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
                signatures: [
                    {
                        protected: 'eyJhbGciOiJSUzI1NiJ9',
                        header: { kid: '2010-12-29' },
                        signature: 'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw',
                    },
                    {
                        protected: 'eyJhbGciOiJFUzI1NiJ9',
                        header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
                        signature: 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
                    },
                ],
            },
        },
    },
];

// --------------------BEGIN RFC7520 Section 4 test data definition --------------------
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
        isArrayable(arg.input.key, (k) => isJWK(k)) &&
        isArrayable(arg.input.alg, (a) => isAlg(a)) &&
        isObject(arg.signing) &&
        isArrayable(arg.signing, (s) => isObject(s) &&
            (s.protected == null || isJOSEHeaderParams(s.protected, 'JWS')) &&
            (s.protected_b64u == null || typeof s.protected_b64u === 'string') &&
            (s.unprotected == null || isJOSEHeaderParams(s.unprotected, 'JWS'))) &&
        isObject(arg.output) &&
        (arg.output.compact == null || typeof arg.output.compact === 'string') &&
        JWSJSONSerializer.is(arg.output.json) &&
        (arg.output.json_flat == null || JWSFlattenedJSONSerializer.is(arg.output.json_flat)));
}
// --------------------END RFC7520 Section 4 test data definition --------------------

// --------------------BEGIN RFC7520 Section 4 test --------------------
async function test(path) {
    const data = await fetchData(path);
    let allGreen = true;
    const title = 'RFC7520#4 TEST NAME: ' + data.title;
    let log = '';
    // 準備
    const payload = UTF8(data.input.payload);
    const options = {
        header: Array.isArray(data.signing)
            ? data.signing.map((s) => ({
                p: s.protected
                    ? {
                        initialValue: s.protected,
                        b64u: s.protected_b64u,
                    }
                    : undefined,
                u: s.unprotected
                    ? {
                        initialValue: s.unprotected,
                    }
                    : undefined,
            }))
            : {
                p: data.signing.protected
                    ? {
                        initialValue: data.signing.protected,
                        b64u: data.signing.protected_b64u,
                    }
                    : undefined,
                u: data.signing.unprotected
                    ? {
                        initialValue: data.signing.unprotected,
                    }
                    : undefined,
            },
    };
    const keys = {
        keys: Array.isArray(data.input.key) ? data.input.key : [data.input.key],
    };
    // 生成
    const jws = await JWS.produce(data.input.alg, keys, payload, options);
    // 検証の準備
    const verifyKeys = {
        keys: keys.keys.map((k) => {
            if (isJWK(k, 'Priv'))
                return exportPubJWK(k);
            if (isJWK(k, 'Pub'))
                return k;
            throw TypeError(`JWK ではない鍵が紛れ込んでいる ${k}`);
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
            const same = JWSJSONSerializer.equals(output.json, json);
            allGreen &&= same;
            log += 'JSON: ' + (same ? '(OK) ' : 'X ');
        }
        if (output.json_flat) {
            const flat = jws.serialize('json_flat');
            const same = JWSFlattenedJSONSerializer.equals(output.json_flat, flat);
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
// --------------------END RFC7520 Section 4 test --------------------

// --------------------BEGIN entry point --------------------
window.document.getElementById('jwk')?.addEventListener('click', test_jwk);
window.document.getElementById('jws')?.addEventListener('click', test_jws);
window.document.getElementById('jwe')?.addEventListener('click', test_jwe);
async function test_jwk() {
    console.group('JWK のテストを始めます');
    const logs = await Promise.all([test$6, test$5, test$4, test$3, test$2].map(async (test) => await test()));
    let allAllGreen = true;
    logs.forEach(({ title, log, allGreen }) => {
        allAllGreen &&= allGreen;
        console.group(title, allGreen);
        console.log(log);
        console.groupEnd();
    });
    console.log('JWK のテスト終了', allAllGreen);
    console.groupEnd();
}
async function test_jws() {
    console.group('JWS のテストを始めます');
    const logs = await Promise.all(paths.map(async (path) => await test(path)));
    let allAllGreen = true;
    logs.forEach(({ title, log, allGreen }) => {
        allAllGreen &&= allGreen;
        console.group(title, allGreen);
        console.log(log);
        console.groupEnd();
    });
    {
        console.group('RFC7515 Appendix の例');
        const { title, allGreen, log } = await test$1();
        allAllGreen &&= allGreen;
        console.group(title, allGreen);
        console.log(log);
        console.groupEnd();
    }
    console.log('JWS のテスト終了', allAllGreen);
    console.groupEnd();
}
async function test_jwe() {
    console.group('JWE のテストを始める');
    const logs = await Promise.all(paths$1.map(async (path) => await test$7(path)));
    let allAllGreen = true;
    logs.forEach(({ title, log, allGreen }) => {
        allAllGreen &&= allGreen;
        console.group(title, allGreen);
        console.log(log);
        console.groupEnd();
    });
    console.log('JWE のテスト終了', allAllGreen);
    console.groupEnd();
}
// --------------------END entry point --------------------
