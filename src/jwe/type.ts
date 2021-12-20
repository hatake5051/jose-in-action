import { JOSEHeaderParams } from 'iana/header';

/**
 * JWECEK は Content Encryption Key を表す.
 * ランダムに生成か、鍵合意に基づく値か、事前共有鍵に基づく値のいずれか
 */
export type JWECEK = Uint8Array & { _brand: 'JWECEK' };

/**
 * JWEEncryptedKey は CEK を暗号化した値を表す
 * CEK を暗号化しない場合(DirectKeyEncrytion or DirectKeyAgreement) は empty octet sequence である。
 */
export type JWEEncryptedKey = Uint8Array & { _brand: 'JWEEncryptedKey' };

/**
 * JWECiphertext はメッセージを暗号化した結果を表現する.
 */
export type JWECiphertext = Uint8Array & { _brand: 'JWECiphertext' };

/**
 * JWETag は認証付き暗号の結果の Authentication Tag を表現する.
 */
export type JWETag = Uint8Array & { _brand: 'JWETag' };

/**
 * JWEAAD は the authenticated encryption operatoion で integrity が保護される Additional Authenticated Data を表す.
 * Compact Serialization では用いることができない.
 */
export type JWEAAD = Uint8Array & { _brand: 'JWEAAD' };

/**
 * JWEIV は Initialization Vector を表す.
 * Content を暗号化するときに使う.
 * IV を使わないアルゴリズムでは the empty octed sequence である。
 */
export type JWEIV = Uint8Array & { _brand: 'JWEIV' };

export type JWEProtectedHeader = JOSEHeaderParams<'JWE'> & { _brand: 'JWEProtectedHeader' };
export type JWESharedUnprotectedHeader = JOSEHeaderParams<'JWE'> & {
  _brand: 'JWESharedUnprotectedHeader';
};
export type JWEPerRecipientUnprotectedHeader = JOSEHeaderParams<'JWE'> & {
  _brand: 'JWEPerRecipientUnprotectedHeader';
};

export type JWECompactSerialization = string;

export type JWEJSONSerialization = {
  protected?: string;
  unprotected?: JWESharedUnprotectedHeader;
  iv?: string;
  aad?: string;
  ciphertext: string;
  tag?: string;
  recipients: {
    header?: JWEPerRecipientUnprotectedHeader;
    encrypted_key?: string;
  }[];
};

export type JWEFlattenedJSONSerialization = {
  protected?: string;
  unprotected?: JWESharedUnprotectedHeader;
  header?: JWEPerRecipientUnprotectedHeader;
  encrypted_key?: string;
  iv?: string;
  aad?: string;
  ciphertext: string;
  tag?: string;
};
