import { EncOperator } from 'jwe/ineterface';
import { JWEAAD, JWECEK, JWECiphertext, JWEIV, JWETag } from 'jwe/type';
import { CONCAT } from 'utility';

export { AGCMEnc, isAGCMEnc, AGCMEncOperator };

const AGCMEncOperator: EncOperator<AGCMEnc> = { enc, dec };
/**
 * jwa#5.3.  Content Encryption with AES GCM
 */
type AGCMEnc = typeof agcmEncList[number];
const isAGCMEnc = (arg: unknown): arg is AGCMEnc => agcmEncList.some((a) => a === arg);
const agcmEncList = ['A128GCM', 'A192GCM', 'A256GCM'] as const;

async function enc(
  enc: AGCMEnc,
  cek: JWECEK,
  iv: JWEIV,
  aad: JWEAAD,
  m: Uint8Array
): Promise<{ c: JWECiphertext; tag: JWETag }> {
  const k = await window.crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);
  const e = new Uint8Array(
    await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, k, m)
  );
  const ciphertext: JWECiphertext = e.slice(0, e.length - 16);
  const tag: JWETag = e.slice(e.length - 16);
  return { c: ciphertext, tag };
}

async function dec(
  enc: AGCMEnc,
  cek: JWECEK,
  iv: JWEIV,
  aad: JWEAAD,
  c: JWECiphertext,
  tag: JWETag
): Promise<Uint8Array> {
  const k = await window.crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);
  const e = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv, additionalData: aad },
    k,
    CONCAT(c, tag)
  );
  return new Uint8Array(e);
}
