'use strict';

const isCommonJWKParams = (arg) => {
    if (typeof arg !== 'object')
        return false;
    if (arg == null)
        return false;
    return 'kty' in arg;
};

// -------------------------------- utility function
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

const ecPublicKeyParams = ['crv', 'x', 'y'];
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
    return (BASE64URL_DECODE(p.x).length === key_len &&
        BASE64URL_DECODE(p.y).length === key_len);
}
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
const isECPublicKey = (arg) => {
    if (!isCommonJWKParams(arg) || arg.kty !== 'EC')
        return false;
    if (!ecPublicKeyParams.every((key) => key in arg))
        return false;
    return validECPublicKeyParams(arg);
};
const isECPrivateKey = (arg) => {
    if (!isECPublicKey(arg))
        return false;
    const crv = arg.crv;
    if (!('d' in arg))
        return false;
    return validECPrivateKeyParams(crv, arg);
};

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
    let log = 'EC鍵かどうか判定します。\n';
    for (const path of urlList) {
        log += `TEST NAME: ${path}: `;
        const data = await fetchData(path);
        if (!path.includes('ec')) {
            if (!isCommonJWKParams(data)) {
                log += 'JWK鍵と判定できていない\n';
                allGreen = false;
            }
            else if (isECPublicKey(data) || isECPrivateKey(data)) {
                log += 'EC鍵ではないはずが、EC鍵だと識別されている。\n';
                allGreen = false;
            }
            else {
                log += 'EC鍵ではないと判定できた(OK)\n';
            }
        }
        else if (path === '3_1.ec_public_key.json') {
            if (!isECPublicKey(data)) {
                console.log(data);
                log += 'EC公開鍵の判定に失敗。\n';
                allGreen = false;
            }
            else {
                log += 'EC公開鍵と判定できた(OK)\n';
            }
            continue;
        }
        else if (path === '3_2.ec_private_key.json') {
            if (!isECPrivateKey(data)) {
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
    return { log, allGreen };
}

// ------------------------------------ entry point
(async () => {
    const { log, allGreen } = await test();
    console.log(allGreen);
    console.log(log);
})();
