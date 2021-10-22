import { isJWKPriv, isJWKPub, isJWKSet, isJWKSym } from '../index';

async function test(): Promise<{
  title: string;
  log: string;
  allGreen: boolean;
}> {
  let allGreen = true;
  const title = 'RFC7517#A Example JSON Web Key Sets;';
  let log = 'TEST NAME: A.1.Example Public Keys: ';
  // JWK Set contains two public keys represented as JWKs
  if (!isJWKSet(a1)) {
    log += 'JWK Set と判定できていない\n';
    allGreen = false;
  } else {
    log += 'JWK Set と判定できた\n';
    // one using an Elliptic Curve algorithm and a second one using an RSA algorithm.
    if (isJWKPub('EC', a1.keys[0]) && isJWKPub('RSA', a1.keys[1])) {
      log += '1つ目の鍵はEC公開鍵で、２つ目の鍵はRSA公開鍵と判定できた\n';
    } else {
      log += 'JWK Set に含まれる公開鍵の種類の判定に失敗\n';
      allGreen = false;
    }
    // The first specifies that the key is to be used for encryption.
    if (a1.keys[0].use === 'enc') {
      log += 'EC公開鍵の使い道が暗号化であることが確認できた\n';
    } else {
      log += 'EC公開鍵の使い道が暗号化であることの判定に失敗\n';
    }
    // The second specifies that the key is to be used with the "RS256" algorithm.
    if (a1.keys[1].alg === 'RS256') {
      log += 'RSA公開鍵のアルゴリズムを判定できた\n';
    } else {
      log += 'RSA公開鍵のアルゴリズムの判定に失敗\n';
    }
  }
  log += 'TEST NAME: A.2. Example Private Keys ';
  if (!isJWKSet(a2)) {
    log += 'JWK Set と判定できていない\n';
    allGreen = false;
  } else {
    log += 'JWK Set と判定できた\n';
    // one using an Elliptic Curve algorithm and a second one using an RSA algorithm.
    if (isJWKPriv('EC', a2.keys[0]) && isJWKPriv('RSA', a2.keys[1])) {
      log += '1つ目の鍵はEC秘密鍵で、２つ目の鍵はRSA秘密鍵と判定できた\n';
    } else {
      log += 'JWK Set に含まれる秘密鍵の種類の判定に失敗\n';
      allGreen = false;
    }
  }
  log += 'TEST NAME: A.3. Example Symmetric Keys ';
  if (!isJWKSet(a3)) {
    log += 'JWK Set と判定できていない\n';
    allGreen = false;
  } else {
    log += 'JWK Set と判定できた\n';
    // JWK Set contains two symmetric keys represented as JWKs:
    if (isJWKSym(a3.keys[0]) && isJWKSym(a3.keys[1])) {
      log += '２つの対称鍵が含まれていることを確認\n';
    } else {
      log += 'JWK Set に含まれる対称鍵の種類の判定に失敗\n';
      allGreen = false;
    }
  }
  return { title, log, allGreen };
}
export { test };

const a1 = {
  keys: [
    {
      kty: 'EC',
      crv: 'P-256',
      x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
      y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      use: 'enc',
      kid: '1',
    },

    {
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
      alg: 'RS256',
      kid: '2011-04-29',
    },
  ],
};

const a2 = {
  keys: [
    {
      kty: 'EC',
      crv: 'P-256',
      x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
      y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      d: '870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE',
      use: 'enc',
      kid: '1',
    },

    {
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISnnD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
      d: 'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q',
      p: '83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs',
      q: '3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk',
      dp: 'G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0',
      dq: 's9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk',
      qi: 'GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU',
      alg: 'RS256',
      kid: '2011-04-29',
    },
  ],
};

const a3 = {
  keys: [
    { kty: 'oct', alg: 'A128KW', k: 'GawgguFyGrWKav7AX4VKUg' },
    {
      kty: 'oct',
      k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
      kid: 'HMAC key used in JWS spec Appendix A.1 example',
    },
  ],
};
