import { EncOperator } from 'jwe/ineterface';
import { JWEAAD, JWECEK, JWECiphertext, JWEIV, JWETag } from 'jwe/type';
import { CONCAT } from 'utility';
import { AGCMEnc } from './encalg';

export { AGCMEncOperator, generateCEKForAGCMEnc };

const AGCMEncOperator: EncOperator<AGCMEnc> = { enc, dec };

async function enc(
  enc: AGCMEnc,
  cek: JWECEK,
  m: Uint8Array,
  aad: JWEAAD,
  iv?: JWEIV
): Promise<{ c: JWECiphertext; tag: JWETag; iv: JWEIV }> {
  if (!iv) {
    iv = window.crypto.getRandomValues(new Uint8Array(12)) as JWEIV;
  }
  const k = await window.crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);
  const e = new Uint8Array(
    await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, k, m)
  );
  const ciphertext = e.slice(0, e.length - 16) as JWECiphertext;
  const tag = e.slice(e.length - 16) as JWETag;
  return { c: ciphertext, tag, iv };
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

function generateCEKForAGCMEnc(enc: AGCMEnc): JWECEK {
  const len = (() => {
    switch (enc) {
      case 'A128GCM':
        return 128 / 8;
      case 'A192GCM':
        return 192 / 8;
      case 'A256GCM':
        return 256 / 8;
    }
  })();
  return window.crypto.getRandomValues(new Uint8Array(len)) as JWECEK;
}
