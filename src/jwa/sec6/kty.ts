export { JWAKty, isJWAKty, JWACrv, isJWACrv };

/**
 * JWAKty は JWA で登録された JSON Web Key Types を列挙する。
 */
type JWAKty = typeof jwaKtyList[number];
const isJWAKty = (arg: unknown): arg is JWAKty => {
  if (typeof arg == 'string') {
    return jwaKtyList.some((k) => k === arg);
  }
  return false;
};

const jwaKtyList = ['EC', 'RSA', 'oct'] as const;

/**
 * JWA で定義された JSON Web Key Elliptic Curve を列挙する。
 */
type JWACrv = typeof jwaCrvList[number];
const isJWACrv = (arg: unknown): arg is JWACrv => {
  if (typeof arg === 'string') {
    return jwaCrvList.some((u) => u === arg);
  }
  return false;
};

const jwaCrvList = ['P-256', 'P-384', 'P-521'] as const;
