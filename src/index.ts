import { BASE64URL, BASE64URL_DECODE, UTF8, UTF8_DECODE } from "./util";

// ------------------------------------ entry point
const header = { alg: 'HS256', typ: 'JWT' };
console.log(UTF8_DECODE(BASE64URL_DECODE(BASE64URL(UTF8(JSON.stringify(header))))));