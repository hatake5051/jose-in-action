// --------------------BEGIN JWA Kty and Crv definition --------------------

export { JWAKty, isJWAKty, JWAKtyList };

const JWAKtyList = ['EC', 'RSA', 'oct'] as const;

/**
 * JWAKty は JWA で登録された JSON Web Key Types を列挙する。
 */
type JWAKty = typeof JWAKtyList[number];

const isJWAKty = (arg: unknown): arg is JWAKty =>
  typeof arg == 'string' && JWAKtyList.some((k) => k === arg);

// --------------------BEGIN JWA Kty and Crv definition --------------------
