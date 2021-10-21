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

const isOctKey = (arg) => {
    if (!isCommonJWKParams(arg) || arg.kty !== 'oct')
        return false;
    return 'k' in arg;
};

const rsaPublicKeyParams = ['n', 'e'];
const isRSAPublicKey = (arg) => {
    if (!isCommonJWKParams(arg) || arg.kty !== 'RSA')
        return false;
    return rsaPublicKeyParams.every((s) => s in arg);
};
const isRSAPrivateKey = (arg) => {
    if (!isRSAPublicKey(arg))
        return false;
    return 'd' in arg;
};

const isJWK = (arg) => isCommonJWKParams(arg);
const isJWKSym = (arg) => isOctKey(arg);
const isJWKPub = (kty, arg) => {
    if (!isJWK(arg))
        return false;
    if (kty !== arg.kty)
        return false;
    switch (arg.kty) {
        case 'EC':
            return isECPublicKey(arg);
        case 'RSA':
            return isRSAPublicKey(arg);
    }
};
const isJWKPriv = (kty, arg) => {
    if (!isJWK(arg))
        return false;
    if (kty !== arg.kty)
        return false;
    switch (arg.kty) {
        case 'EC':
            return isECPrivateKey(arg);
        case 'RSA':
            return isRSAPrivateKey(arg);
    }
};
const isJWKSet = (arg) => {
    if (typeof arg !== 'object')
        return false;
    if (arg == null)
        return false;
    return 'keys' in arg && Array.isArray(arg.keys);
};

async function test$3() {
    let allGreen = true;
    const title = 'RFC7517#A Example JSON Web Key Sets;';
    let log = 'TEST NAME: A.1.Example Public Keys: ';
    // JWK Set contains two public keys represented as JWKs
    if (!isJWKSet(a1)) {
        log += 'JWK Set と判定できていない\n';
        allGreen = false;
    }
    else {
        log += 'JWK Set と判定できた\n';
        // one using an Elliptic Curve algorithm and a second one using an RSA algorithm.
        if (isJWKPub('EC', a1.keys[0]) && isJWKPub('RSA', a1.keys[1])) {
            log += '1つ目の鍵はEC公開鍵で、２つ目の鍵はRSA公開鍵と判定できた\n';
        }
        else {
            log += 'JWK Set に含まれる公開鍵の種類の判定に失敗\n';
            allGreen = false;
        }
        // The first specifies that the key is to be used for encryption.
        if (a1.keys[0].use === 'enc') {
            log += 'EC公開鍵の使い道が暗号化であることが確認できた\n';
        }
        else {
            log += 'EC公開鍵の使い道が暗号化であることの判定に失敗\n';
        }
        // The second specifies that the key is to be used with the "RS256" algorithm.
        if (a1.keys[1].alg === 'RS256') {
            log += 'RSA公開鍵のアルゴリズムを判定できた\n';
        }
        else {
            log += 'RSA公開鍵のアルゴリズムの判定に失敗\n';
        }
    }
    log += 'TEST NAME: A.2. Example Private Keys ';
    if (!isJWKSet(a2)) {
        log += 'JWK Set と判定できていない\n';
        allGreen = false;
    }
    else {
        log += 'JWK Set と判定できた\n';
        // one using an Elliptic Curve algorithm and a second one using an RSA algorithm.
        if (isJWKPriv('EC', a2.keys[0]) && isJWKPriv('RSA', a2.keys[1])) {
            log += '1つ目の鍵はEC秘密鍵で、２つ目の鍵はRSA秘密鍵と判定できた\n';
        }
        else {
            log += 'JWK Set に含まれる秘密鍵の種類の判定に失敗\n';
            allGreen = false;
        }
    }
    log += 'TEST NAME: A.3. Example Symmetric Keys ';
    if (!isJWKSet(a3)) {
        log += 'JWK Set と判定できていない\n';
        allGreen = false;
    }
    else {
        log += 'JWK Set と判定できた\n';
        // JWK Set contains two symmetric keys represented as JWKs:
        if (isJWKSym(a3.keys[0]) && isJWKSym(a3.keys[1])) {
            log += '２つの対称鍵が含まれていることを確認\n';
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
            if (!isJWK(data)) {
                log += 'JWK鍵と判定できていない\n';
                allGreen = false;
            }
            else if (isJWKPub('EC', data) || isJWKPriv('EC', data)) {
                log += 'EC鍵ではないはずが、EC鍵だと識別されている。\n';
                allGreen = false;
            }
            else {
                log += 'EC鍵ではないと判定できた(OK)\n';
            }
        }
        else if (path === '3_1.ec_public_key.json') {
            if (!isJWKPub('EC', data)) {
                log += 'EC公開鍵の判定に失敗。\n';
                allGreen = false;
            }
            else {
                log += 'EC公開鍵と判定できた(OK)\n';
            }
            continue;
        }
        else if (path === '3_2.ec_private_key.json') {
            if (!isJWKPriv('EC', data)) {
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
            if (!isJWK(data)) {
                log += 'JWK鍵と判定できていない\n';
                allGreen = false;
            }
            else if (isJWKSym(data)) {
                log += 'oct鍵ではないはずが、oct鍵だと識別されている。\n';
                allGreen = false;
            }
            else {
                log += 'oct鍵ではないと判定できた(OK)\n';
            }
        }
        else if (path === '3_5.symmetric_key_mac_computation.json') {
            if (!isJWKSym(data)) {
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
            if (!isJWKSym(data)) {
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
            if (!isJWK(data)) {
                log += 'JWK鍵と判定できていない\n';
                allGreen = false;
            }
            else if (isJWKPub('RSA', data) || isJWKPriv('RSA', data)) {
                log += 'RSA鍵ではないはずが、RSA鍵だと識別されている。\n';
                allGreen = false;
            }
            else {
                log += 'RSA鍵ではないと判定できた(OK)\n';
            }
        }
        else if (path === '3_3.rsa_public_key.json') {
            if (!isJWKPub('RSA', data)) {
                log += 'RSA公開鍵の判定に失敗。\n';
                allGreen = false;
            }
            else {
                log += 'RSA公開鍵と判定できた(OK)\n';
            }
            continue;
        }
        else if (path === '3_4.rsa_private_key.json') {
            if (!isJWKPriv('RSA', data)) {
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

// ------------------------------------ entry point
(async () => {
    for (const test$4 of [test$3, test$2, test$1, test]) {
        const { title, log, allGreen } = await test$4();
        console.group(title, 'AllGreen?', allGreen);
        console.log(log);
        console.groupEnd();
    }
})();
