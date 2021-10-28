import { JWSHeader } from './header';
import { isJWSMACAlg, JWSMACAlg } from './mac';
import { isJWSSigAlg, JWSSigAlg } from './sig';

export { JWSHeaderAndSig, JWSPayload, JWSSignature, JWSAlg, isJWSAlg };

/**
 * 保護されるオクテット列（別名メッセージ）。
 * ペイロードは任意のオクテット列を含めることができる。
 */
type JWSPayload = Uint8Array;

/**
 * JWSHeader と、それに基づいて JWAPayload に署名した値である JWSSignature からなるペア。
 * JWS は複数の署名持つことができるのでこの単位でまとめている。
 */
type JWSHeaderAndSig = { h: JWSHeader; s?: JWSSignature };

/**
 * JWS Protected Header と JWS Payload に対するデジタル署名もしくは MAC。
 */
type JWSSignature = Uint8Array;

/**
 * JWS のために定義されたアルゴリズムを列挙する。
 */
type JWSAlg = JWSSigAlg | JWSMACAlg | 'none';

const isJWSAlg = (arg: unknown): arg is JWSAlg =>
  isJWSSigAlg(arg) || isJWSMACAlg(arg) || (typeof arg === 'string' && arg === 'none');
