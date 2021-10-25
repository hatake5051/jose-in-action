'use strict';

// --------------------BEGIN iana constants --------------------
/**
 * Kty は JSON Web Key Types を列挙する。
 * 'OKP' は未実装である。
 */
const ktyList = ['EC', 'RSA', 'oct'];
const isKty = (arg) => {
    if (typeof arg == 'string') {
        return ktyList.some((k) => k === arg);
    }
    return false;
};
// --------------------END iana constants --------------------

// --------------------BEGIN JWK common parameters --------------------
/**
 * 共通パラメータのうち JWK として必須なものを引数が持っているか確認する。
 * RFC7517 では kty が必須とされている。
 */
const isCommonJWKParams = (arg) => {
    if (typeof arg !== 'object' || arg == null)
        return false;
    if ('kty' in arg) {
        return isKty(arg.kty);
    }
    return false;
};
// --------------------END JWK common parameters --------------------

// --------------------BEGIN util functions --------------------
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
// --------------------END util functions --------------------

// --------------------BEGIN JWK EC parameters --------------------
/**
 * 引数が EC公開鍵の JWK 表現か確認する。
 * kty == EC かどうか、 crv に適した x,y のサイズとなっているかどうか。
 */
const isECPublicKey = (arg) => {
    if (!isCommonJWKParams(arg) || arg.kty !== 'EC')
        return false;
    if (!ecPublicKeyParams.every((key) => key in arg))
        return false;
    return validECPublicKeyParams(arg);
};
/**
 * 引数が EC 秘密鍵の JWK 表現か確認する。
 * EC 公開鍵であり、かつ d をパラメータとして持っていれば。
 */
const isECPrivateKey = (arg) => {
    if (!isECPublicKey(arg))
        return false;
    const crv = arg.crv;
    if (!('d' in arg))
        return false;
    return validECPrivateKeyParams(crv, arg);
};
const ecPublicKeyParams = ['crv', 'x', 'y'];
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
// --------------------END JWK EC parameters --------------------

// --------------------BEGIN JWK oct parameters --------------------
/**
 * 引数が対称鍵か確認する。
 * kty == oct で k をパラメータとして持つか確認する。
 */
const isOctKey = (arg) => {
    if (!isCommonJWKParams(arg) || arg.kty !== 'oct')
        return false;
    return 'k' in arg;
};
// --------------------END JWK oct parameters --------------------

// --------------------BEGIN JWK RSA parameters --------------------
/**
 * 引数が RSA 公開鍵かどうか確認する。
 * kty == RSA かどうか、 n,e をパラメータとしてもつか確認する。
 */
const isRSAPublicKey = (arg) => {
    if (!isCommonJWKParams(arg) || arg.kty !== 'RSA')
        return false;
    return rsaPublicKeyParams.every((s) => s in arg);
};
/**
 * 引数が RSA 秘密鍵かどうか確認する。
 * RSA 公開鍵であるか、また d をパラメータとして持つか確認する。
 */
const isRSAPrivateKey = (arg) => {
    if (!isRSAPublicKey(arg))
        return false;
    return 'd' in arg;
};
const rsaPublicKeyParams = ['n', 'e'];
// --------------------END JWK RSA parameters --------------------

// --------------------BEGIN JWK definition --------------------
/**
 * 引数が JWK オブジェクトであるかどうか確認する。
 * kty を指定するとその鍵タイプの JWK 形式を満たすか確認する。
 * asym を指定すると非対称暗号鍵のうち指定した鍵（公開鍵か秘密鍵）かであるかも確認する。
 */
function isJWK(arg, kty, asym) {
    switch (kty) {
        // kty を指定しないときは、最低限 JWK が持つべき情報を持っているか確認する
        case undefined:
            return isCommonJWKParams(arg);
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
// --------------------END JWK definition --------------------

// --------------------BEGIN RFC7517 appendix.A test --------------------
async function test$3() {
    let allGreen = true;
    const title = 'RFC7517#A Example JSON Web Key Sets;';
    let log = 'TEST NAME: A.1.Example Public Keys: ';
    // JWK Set contains two public keys represented as JWKs
    {
        log += 'JWK Set と判定できていない\n';
        allGreen = false;
    }
    log += 'TEST NAME: A.2. Example Private Keys: ';
    {
        log += 'JWK Set と判定できていない\n';
        allGreen = false;
    }
    log += 'TEST NAME: A.3. Example Symmetric Keys: ';
    {
        log += 'JWK Set と判定できていない\n';
        allGreen = false;
    }
    return { title, log, allGreen };
}
// --------------------END RFC7517 appendix.A test --------------------

// --------------------BEGIN RFC7520 Section.3 for EC test --------------------
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
async function test() {
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

// --------------------BEGIN entry point --------------------
(async () => {
    for (const test$4 of [test$3, test$2, test$1, test]) {
        const { title, log, allGreen } = await test$4();
        console.group(title, allGreen);
        console.log(log);
        console.groupEnd();
    }
})();
// --------------------END entry point --------------------
