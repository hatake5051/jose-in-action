// --------------------BEGIN JWA Kty and Crv definition --------------------

export { JWAKty, isJWAKty, JWACrv, isJWACrv };

/**
 * JWAKty は JWA で登録された JSON Web Key Types を列挙する。
 */
type JWAKty = typeof jwaKtyList[number];

const isJWAKty = (arg: unknown): arg is JWAKty =>
  typeof arg == 'string' && jwaKtyList.some((k) => k === arg);

const jwaKtyList = ['EC', 'RSA', 'oct'] as const;

/**
 * JWA で定義された JSON Web Key Elliptic Curve を列挙する。
 */
type JWACrv = typeof jwaCrvList[number];

const isJWACrv = (arg: unknown): arg is JWACrv =>
  typeof arg === 'string' && jwaCrvList.some((u) => u === arg);

const jwaCrvList = ['P-256', 'P-384', 'P-521'] as const;

// --------------------BEGIN JWA Kty and Crv definition --------------------
