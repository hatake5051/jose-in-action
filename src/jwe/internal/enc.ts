import { Alg } from 'iana';
import { JWEAAD, JWECEK, JWECiphertext, JWEIV, JWETag } from 'jwe';

export { EncOperator };

interface EncOperator<E extends Alg> {
  enc: (
    enc: E,
    cek: JWECEK,
    iv: JWEIV,
    aad: JWEAAD,
    m: Uint8Array
  ) => Promise<{ c: JWECiphertext; tag: JWETag }>;
  dec: (
    enc: E,
    cek: JWECEK,
    iv: JWEIV,
    aad: JWEAAD,
    c: JWECiphertext,
    tag: JWETag
  ) => Promise<Uint8Array>;
}
