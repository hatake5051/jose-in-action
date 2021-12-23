import { JOSEHeaderParams } from 'iana/header';

/**
 * 保護されるオクテット列（別名メッセージ）。
 * ペイロードは任意のオクテット列を含めることができる。
 */
export type JWSPayload = Uint8Array & { _brand: 'JWSPayload' };

/**
 * JWS Protected Header と JWS Payload に対するデジタル署名もしくは MAC。
 */
export type JWSSignature = Uint8Array & { _brand: 'JWSSignature' };

/**
 * JWS Signature によって完全性を保護されるヘッダーパラメータを含む JSON オブジェクト。
 */
export type JWSProtectedHeader = JOSEHeaderParams<'JWS'> & { _brand: 'JWSProtectedHeader' };

/**
 * 完全性を保護されないヘッダーパラメータを含む JSON オブジェクト。
 */
export type JWSUnprotectedHeader = JOSEHeaderParams<'JWS'> & { _brand: 'JWSUnprotectedHeader' };

/**
 * JWS を URL-safe な文字列をする serialization
 * 署名は１つだけしか表現できず、 Unprotected Header も表現できない
 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
 * で表現する。
 */
export type JWSCompactSerialization = string;

/**
 * JSON で Serialization する
 * コンパクトでもないし、 url-safe でもないが表現に制限はない。
 */
export type JWSJSONSerialization = {
  /**
   * BASE64URL(JWS Payload)
   */
  payload: string;
  /**
   * 署名を表現するオブジェクトの配列
   */
  signatures: {
    /**
     * BASE64URL(JWS Signature)
     */
    signature: string;
    /**
     * UNprotected Header があればそのまま JSON でシリアライズ。
     * ないときは存在してはならない。
     */
    header?: JWSUnprotectedHeader;
    /**
     * Protected Header があれば BASE64URL(UTF8(JWS Protected Header)) デシリアライズ。
     * ないときは存在してはならない。
     */
    protected?: string;
  }[];
};

/**
 * 署名が１つだけの時に、JSON serialization は平滑化できる。
 * signatures は存在してはならない。
 */
export type JWSFlattenedJSONSerialization = {
  payload: string;
  signature: string;
  header?: JWSUnprotectedHeader;
  protected?: string;
};
