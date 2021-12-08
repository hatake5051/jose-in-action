export { JWECEK, JWEEncryptedKey, JWECiphertext, JWETag, JWEAAD, JWEIV };

/**
 * JWECEK は Content Encryption Key を表す.
 * ランダムに生成か、鍵合意に基づく値か、事前共有鍵に基づく値のいずれか
 */
type JWECEK = Uint8Array;

/**
 * JWEEncryptedKey は CEK を暗号化した値を表す
 * CEK を暗号化しない場合(DirectKeyEncrytion or DirectKeyAgreement) は empty octet sequence である。
 */
type JWEEncryptedKey = Uint8Array;

/**
 * JWECiphertext はメッセージを暗号化した結果を表現する.
 */
type JWECiphertext = Uint8Array;

/**
 * JWETag は認証付き暗号の結果の Authentication Tag を表現する.
 */
type JWETag = Uint8Array;

/**
 * JWEAAD は the authenticated encryption operatoion で integrity が保護される Additional Authenticated Data を表す.
 * Compact Serialization では用いることができない.
 */
type JWEAAD = Uint8Array;

/**
 * JWEIV は Initialization Vector を表す.
 * Content を暗号化するときに使う.
 * IV を使わないアルゴリズムでは the empty octed sequence である。
 */
type JWEIV = Uint8Array;
