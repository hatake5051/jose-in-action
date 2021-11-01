export { JWECEK, JWEEncryptedKey };

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
