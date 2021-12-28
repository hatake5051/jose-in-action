/**
 * @file 便利な関数を他に提供する
 */

/**
 * 文字列を UTF8 バイトエンコードする。(string to Uint8Array)
 * @param {string} STRING - 文字列
 * @return {Uint8Array} UTF8 バイト列
 */
export function UTF8(STRING: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(STRING);
}

/**
 * 文字列に UTF8 バイトデコードする (Uint8Array to string)
 * @param {Uint8Array} OCTETS - UTF8 バイト列
 * @return {string} 文字列
 */
export function UTF8_DECODE(OCTETS: Uint8Array): string {
  const decoder = new TextDecoder();
  return decoder.decode(OCTETS);
}

/**
 * 文字列を ASCII バイトエンコードする。 (string to Uint8Array)
 * @param {string} STRING - ASCII文字列
 * @return {Uint8Array} ASCII バイト列
 * @throws ASCII 文字ではないものが含まれていると TypeError を吐く
 */
export function ASCII(STRING: string): Uint8Array {
  const b = new Uint8Array(STRING.length);
  for (let i = 0; i < STRING.length; i++) {
    const bb = STRING.charCodeAt(i);
    if (bb > 127) {
      throw new TypeError(`ASCII ではない文字が含まれている: ${STRING.charAt(i)}`);
    }
    b[i] = bb;
  }
  return b;
}

/**
 * バイト列を BASE64URL エンコードする (Uint8Array to string)
 * @param {Uint8Array} OCTETS - バイト列
 * @return {string} バイト列の BASE64 URL エンコーディング文字列
 */
export function BASE64URL(OCTETS: Uint8Array): string {
  // window 組み込みの base64 encode 関数
  // 組み込みの関数は引数としてバイナリ文字列を要求するため
  // Uint8Array をバイナリ文字列へと変換する
  const b_str = String.fromCharCode(...OCTETS);
  const base64_encode = window.btoa(b_str);
  return (
    base64_encode
      // 文字「+」は全て「-」へ変換する
      .replaceAll('+', '-')
      // 文字「/」は全て「_」へ変換する
      .replaceAll('/', '_')
      // 4の倍数にするためのパディング文字は全て消去
      .replaceAll('=', '')
  );
}

/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
 * @param {string} STRING - BASE64 URL エンコーディング文字列
 * @return {Uint8Array} バイト列
 * @throws STRING が正しい BASE64 URL 文字列ではない時 TypeError を吐く
 */
export function BASE64URL_DECODE(STRING: string): Uint8Array {
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
  } catch (e: unknown) {
    throw new TypeError(`与えられた文字列 ${STRING} は base64url encoded string ではない`);
  }
}

/**
 * ２つのバイト列を結合する
 * @param {Uint8Array} A - 先頭バイト列
 * @param {Uint8Array} B - 後続バイト列
 * @return {Uint8Array} A の後ろに B をつなげたバイト列 A || B
 */
export function CONCAT(A: Uint8Array, B: Uint8Array): Uint8Array {
  const ans = new Uint8Array(A.length + B.length);
  ans.set(A);
  ans.set(B, A.length);
  return ans;
}

/**
 * T のプロパティを全て unknown | undefined 型に変える
 */
type WouldBe<T> = { [P in keyof T]?: unknown };

/**
 * value を WouldBE<T> かどうか判定する。
 * T のプロパティを持つかもしれないところまで。
 * ref: https://qiita.com/suin/items/e0f7b7add75092196cd8
 * @template T
 * @param {unknown} value - 型ガード対象の値
 * @return {value is WouldBe<T>} value が WouldBe<T> なら true
 */
export const isObject = <T extends object>(value: unknown): value is WouldBe<T> =>
  typeof value === 'object' && value !== null;

/**
 * T もしくは Array<T> のいずれかである型
 */
export type Arrayable<T> = T | Array<T>;

/**
 * T が配列ならその要素を、そうでない時はそのものの型を表す
 */
export type Flatten<T> = T extends Array<infer E> ? E : T;

/**
 * 型ガード関数
 * @template T
 * @param {unknown} arg - 型ガード対象の値
 * @param {(u: unknown) => u is T} f - 引数が T であるか判定する型ガード関数
 * @return {arg is Arrayable<T>} arg が Arrayable<T> なら true
 */
export const isArrayable = <T>(arg: unknown, f: (u: unknown) => u is T): arg is Arrayable<T> => {
  return Array.isArray(arg) ? arg.every(f) : f(arg);
};
