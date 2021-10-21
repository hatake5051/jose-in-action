'use strict';

// -------------------------------- utility function
function UTF8(STRING) {
    const encoder = new TextEncoder();
    return encoder.encode(STRING);
}
function UTF8_DECODE(OCTETS) {
    const decoder = new TextDecoder();
    return decoder.decode(OCTETS);
}
function BASE64URL(OCTETS) {
    // window 組み込みの base64 encode 関数
    // 組み込みの関数は引数としてバイナリ文字列を要求するため
    // Uint8Array をバイナリ文字列へと変換する
    const b_str = String.fromCharCode(...OCTETS);
    const base64_encode = window.btoa(b_str);
    return base64_encode
        // 文字「+」は全て「-」へ変換する
        .replaceAll("+", "-")
        // 文字「/」は全て「_」へ変換する
        .replaceAll("/", "_")
        // 4の倍数にするためのパディング文字は全て消去
        .replaceAll("=", "");
}
function BASE64URL_DECODE(STRING) {
    const url_decode = STRING
        // URL-safe にするために変換した文字たちを戻す
        .replaceAll("-", "+")
        .replaceAll("_", "/")
        // 文字列長が4の倍数になるように padding文字で埋める
        .padEnd(Math.ceil(STRING.length / 4) * 4, "=");
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

// ------------------------------------ entry point
const header = { alg: 'HS256', typ: 'JWT' };
console.log(UTF8_DECODE(BASE64URL_DECODE(BASE64URL(UTF8(JSON.stringify(header))))));
