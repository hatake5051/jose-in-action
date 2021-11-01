export { JWECEK, JWEEncryptedKey, JWECiphertext, JWETag, JWEAAD, JWEIV };

/**
 * JWECEK は Content Encryption Key を表す.
 * ランダムに生成か、鍵合意に基づく値か、事前共有鍵に基づく値のいずれか
 */
type JWECEK = Uint8Array;

/**
 * JWEEncryptedKey は CEK を暗号化した結果を表す.
 * CEK を暗号化しない場合(DirectKeyEncrytion or DirectKeyAgreement) は omit される
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
 * JWEAAD は Additional Authenticated Data を表す.
 * Compact Format 化する際は用いることができない.
 */
type JWEAAD = Uint8Array;

/**
 * JWEIV は Initialization Vector を表す.
 * Content を暗号化するときに使う.
 */
type JWEIV = Uint8Array;
