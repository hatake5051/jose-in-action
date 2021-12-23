import { isJWAKty, JWAKty, JWAKtyList } from 'jwa/sec6/kty';

export { Kty, isKty, KtyList };

/**
 * Kty は JSON Web Key Types を列挙する。
 * 'OKP' は未実装である。
 */
type Kty = JWAKty;
const isKty = (arg: unknown): arg is Kty => isJWAKty(arg);

const KtyList = [...JWAKtyList] as const;
