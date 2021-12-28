import { KeyUse } from 'iana/key_ops';
import { Kty } from 'iana/kty';
import { JWK } from './jwk';
import { JWKSet } from './jwkset';

export { identifyJWK, verifyJWK };

function identifyJWK(
  jwks: JWKSet,
  policy: {
    kty?: Kty;
    kid?: string;
  }
): JWK {
  let filtered = jwks.keys;
  if (policy.kty) {
    filtered = filtered.filter((key) => policy.kty === key.kty);
    if (filtered.length === 1 && filtered[0]) return filtered[0];
  }
  if (policy.kid) {
    filtered = filtered.filter((key) => policy.kid === key.kid);
    if (filtered.length === 1 && filtered[0]) return filtered[0];
  }
  throw new EvalError(`cannot identify from JWKSet using policy ${JSON.stringify(policy)}`);
}

async function verifyJWK(
  jwk: JWK,
  policy: {
    use?: KeyUse;
    // x5c?: {
    //   selfSigned?: boolean;
    // };
  }
): Promise<boolean> {
  if (policy.use) {
    if (policy.use !== jwk.use) return false;
  }
  // if (policy.x5c) {
  //   const err = await verifyJWK_x5c(jwk, policy.x5c);
  //   if (err) return false;
  // }
  return true;
}

/**
 * 型で表現しきれない JWK の条件を満たすか確認する。
 * options に渡された条件を jwk が満たすか確認する
 * options.x5c を渡すことで、 jwk.x5c があればそれを検証する。
 * options.x5c.selfSigned = true にすると、x5t が自己署名証明書だけを持つか確認し、
 * 署名が正しいか確認する。また jwk パラメータと同じ内容が書かれているか確認する。
 */
// async function verifyJWK_x5c(
//   jwk: JWK,
//   policy: { selfSigned?: boolean }
// ): Promise<string | undefined> {
//   if (!jwk.x5c) return 'JWK.x5c parameter is not found';
//   if (jwk.x5c[0] && !policy.selfSigned) return 'JWK.x5c is self-signed certificate';
//   // The key in the first certificate MUST match the public key represented by other members of the JWK. (RFC7517)
//   // jwk.x5c[0] が表現する公開鍵はその jwk が表現する値と同じでなければならない
//   const crt1 = parseX509BASE64EncodedDER(jwk.x5c[0]);

//   switch (jwk.kty) {
//     case 'RSA':
//       if (
//         isJWK(jwk, 'RSA') &&
//         crt1.tbs.spki.kty === 'RSA' &&
//         isX509SPKI(crt1.tbs.spki, 'RSA') &&
//         jwk.n === BASE64URL(crt1.tbs.spki.n) &&
//         jwk.e === BASE64URL(crt1.tbs.spki.e)
//       ) {
//         break;
//       }
//       return 'JWK.x5c[0] does not match with JWK parameteres';
//     case 'EC':
//       if (
//         isJWK(jwk, 'EC') &&
//         crt1.tbs.spki.kty === 'EC' &&
//         isX509SPKI(crt1.tbs.spki, 'EC') &&
//         jwk.x === BASE64URL(crt1.tbs.spki.x) &&
//         jwk.y === BASE64URL(crt1.tbs.spki.y)
//       ) {
//         break;
//       }
//       return 'JWK.x5c[0] does not match with JWK parameteres';
//     case 'oct':
//       return 'JWK.x5c does not support symmetric key representation';
//   }

//   if (jwk.x5c.length > 1)
//     throw EvalError('証明書チェーンが１の長さで、かつ自己署名の場合のみ実装している');
//   const crt = parseX509BASE64EncodedDER(jwk.x5c[0]);
//   if (!(await validateSelfSignedCert(crt))) {
//     return 'JWK.x5c Signature Verification Error';
//   }
// }
