export { JWACrv, isJWACrv, keylenOfJWACrv };
/**
 * JWA で定義された JSON Web Key Elliptic Curve を列挙する。
 */
type JWACrv = typeof jwaCrvList[number];

const isJWACrv = (arg: unknown): arg is JWACrv =>
  typeof arg === 'string' && jwaCrvList.some((u) => u === arg);

const jwaCrvList = ['P-256', 'P-384', 'P-521'] as const;

function keylenOfJWACrv(crv: JWACrv): number {
  switch (crv) {
    case 'P-256':
      return 32;
    case 'P-384':
      return 48;
    case 'P-521':
      return 66;
  }
}
