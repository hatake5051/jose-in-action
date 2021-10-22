'use strict';

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

const isCommonJWKParams = (arg) => {
    if (typeof arg !== 'object' || arg == null)
        return false;
    if ('kty' in arg) {
        return isKty(arg.kty);
    }
    return false;
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

const TAG_SEQUENCE = 16;
const TAG_BITSTRING = 3;
const TAG_OBJECTIDENTIFIER = 6;
/**
 * X.509 Certificate を表す、BASE64 エンコードされた DER をパースする
 */
function parseX509BASE64EncodedDER(der_b64) {
    return parseX509DER(BASE64_DECODE(der_b64));
}
async function validateSelfSignedCert(crt) {
    // alg を識別する
    const alg = crt.sigAlg.join('.');
    if (alg !== crt.tbs.alg.join('.')) {
        throw EvalError('signatureAlgorithm !== TBSCertificate.signature エラー');
    }
    // for Public-Key Cryptography Standards (PKCS) OID
    if (alg.startsWith('1.2.840.113549.1.1')) {
        let keyAlg;
        let verifyAlg;
        if (alg === '1.2.840.113549.1.1.5') {
            // sha1-with-rsa-signature とか sha1WithRSAEncryption
            keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' };
            verifyAlg = 'RSASSA-PKCS1-v1_5';
        }
        else if (alg === '1.2.840.113549.1.1.11') {
            // sha256WithRSAEncryption
            keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
            verifyAlg = 'RSASSA-PKCS1-v1_5';
        }
        else {
            throw EvalError(`unimplemented rsa alg(${alg})`);
        }
        const pubkey = await crypto.subtle.importKey('spki', crt.tbs.spki, keyAlg, false, ['verify']);
        return crypto.subtle.verify(verifyAlg, pubkey, crt.sig, crt.tbs.raw);
    }
    throw EvalError(`unimplemented alg(${alg})`);
}
function parseX509DER(der_raw) {
    const der = DER_DECODE(der_raw);
    if (der.class !== 'Universal' ||
        der.pc !== 'Constructed' ||
        der.tag !== TAG_SEQUENCE) {
        throw EvalError('X509Cert DER フォーマットを満たしていない');
    }
    const tbs_der = DER_DECODE(der.value);
    const sigalg_der = DER_DECODE(der.value.slice(tbs_der.entireLen));
    const sigAlg = convertDotNotationFromOID(DER_DECODE(sigalg_der.value));
    const sig_der = DER_DECODE(der.value.slice(tbs_der.entireLen + sigalg_der.entireLen));
    return {
        tbs: parseX509TBSCert(tbs_der),
        sigAlg,
        sig: extractBytesFromBITSTRING(sig_der),
    };
}
/**
 * X509 tbsCertificate の DER 表現をパースする
 */
function parseX509TBSCert(der) {
    // TBSCert は SEQUENCE で表される
    if (der.class !== 'Universal' ||
        der.pc !== 'Constructed' ||
        der.tag !== TAG_SEQUENCE) {
        throw EvalError('X509TBSCert DER フォーマットを満たしていない');
    }
    // 一番初めは Version
    const version = DER_DECODE(der.value);
    let start = version.entireLen;
    // 次は Serial Number
    const serialNumber = DER_DECODE(der.value.slice(start));
    start += serialNumber.entireLen;
    const signature = DER_DECODE(der.value.slice(start));
    start += signature.entireLen;
    const issuer = DER_DECODE(der.value.slice(start));
    start += issuer.entireLen;
    const validity = DER_DECODE(der.value.slice(start));
    start += validity.entireLen;
    const subject = DER_DECODE(der.value.slice(start));
    start += subject.entireLen;
    const subjectPublicKeyInformation = DER_DECODE(der.value.slice(start));
    return {
        raw: der.raw,
        alg: convertDotNotationFromOID(DER_DECODE(signature.value)),
        spki: subjectPublicKeyInformation.raw,
    };
}
// ref: http://websites.umich.edu/~x509/ssleay/layman.html
/**
 * DER で表現された BITString からバイナリを取り出す
 */
function extractBytesFromBITSTRING(der) {
    if (der.class !== 'Universal' ||
        der.pc !== 'Primitive' ||
        der.tag !== TAG_BITSTRING) {
        throw EvalError('BITSTRING ではない DER format を扱おうとしている');
    }
    const v = der.value;
    // 先頭のオクテットはbit-length を８の倍数にするためにケツに追加した 0-padding の数を表現する
    if (v[0] === 0x00)
        return v.slice(1);
    // 先頭のオクテットが０でないときは、その数だけ padding 処理を行う
    const contentWithPadEnd = v
        .slice(1)
        .reduce((sum, i) => sum + i.toString(2).padStart(8, '0'), '');
    const content = contentWithPadEnd.slice(0, contentWithPadEnd.length - v[0]);
    const contentWithPadStart = '0'.repeat(v[0]) + content;
    const ans = new Uint8Array(contentWithPadStart.length / 8);
    for (let i = 0; i < ans.length; i++) {
        ans[i] = parseInt(contentWithPadStart.substr(i * 8, 8), 2);
    }
    return ans;
}
/**
 * OID の DER 表現から Object Identifier のドット表記をパースする。
 */
function convertDotNotationFromOID(der) {
    if (der.class !== 'Universal' ||
        der.pc !== 'Primitive' ||
        der.tag !== TAG_OBJECTIDENTIFIER) {
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
function BASE64_DECODE(STRING) {
    const b_str = window.atob(STRING);
    // バイナリ文字列を Uint8Array に変換する
    const b = new Uint8Array(b_str.length);
    for (let i = 0; i < b_str.length; i++) {
        b[i] = b_str.charCodeAt(i);
    }
    return b;
}

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
async function validX5CinJWKPub(jwk) {
    if (jwk.x5c == null)
        return true;
    if (jwk.x5c.length > 1)
        throw EvalError('証明書チェーンが１の長さで、かつ自己署名の場合のみ実装している');
    const crt = parseX509BASE64EncodedDER(jwk.x5c[0]);
    if (!(await validateSelfSignedCert(crt))) {
        return false;
    }
    // X.509 crt と jwk の値の比較をする
    if (jwk.kty === 'RSA') {
        let keyAlg;
        if (crt.sigAlg.join('.') === '1.2.840.113549.1.1.5') {
            // sha1-with-rsa-signature とか sha1WithRSAEncryption
            keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' };
        }
        else if (crt.sigAlg.join('.') === '1.2.840.113549.1.1.11') {
            // sha256WithRSAEncryption
            keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
        }
        else {
            throw EvalError(`validateSelfSignedCert の実装よりここには到達しない`);
        }
        const pubkey = await window.crypto.subtle.importKey('spki', crt.tbs.spki, keyAlg, true, ['verify']);
        const crt_jwk = await window.crypto.subtle.exportKey('jwk', pubkey);
        return jwk.n === crt_jwk.n && jwk.e === crt_jwk.e;
    }
    if (jwk.kty === 'EC') {
        throw EvalError(`EC鍵を持つ x509crt の検証は未実装`);
    }
    return false;
}
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

async function test$4() {
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

async function test$3() {
    let allGreen = true;
    const title = 'RFC7517#B.Example Use of "x5c" Parameter;';
    let log = 'TEST NAME: Self Signed Certificate Verification: ';
    const cert = parseX509BASE64EncodedDER(b.x5c[0]);
    const isVerified = await validateSelfSignedCert(cert);
    if (isVerified) {
        log += 'X509証明書のパースと検証に成功\n';
    }
    else {
        log += 'X509証明書のパースと検証に失敗\n';
        allGreen = false;
    }
    log += 'TEST NAME: Validate JWK.x5c: ';
    if (isJWKPub('RSA', b)) {
        if (await validX5CinJWKPub(b)) {
            log += 'JWK.x5c の検証と整合性の確認に成功\n';
        }
        else {
            log += 'JWK.x5c の検証に失敗\n';
            allGreen = false;
        }
    }
    else {
        log += 'JWKPub<RSA> のパースに失敗\n';
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
            if (isJWKPub('RSA', key)) {
                if (await validX5CinJWKPub(key)) {
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
    for (const test$5 of [test$4, test$3, test$2, test$1, test]) {
        const { title, log, allGreen } = await test$5();
        console.group(title, 'AllGreen?', allGreen);
        console.log(log);
        console.groupEnd();
    }
})();
