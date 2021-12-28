import { exportPubJWK, isJWK, JWK, JWKSet } from 'jwk';
import { JWS, JWSJSONSerializer } from 'jws';
import {
  JWSJSONSerialization,
  JWSPayload,
  JWSProtectedHeader,
  JWSUnprotectedHeader,
} from 'jws/type';

export { test };

async function test(): Promise<{
  title: string;
  log: string;
  allGreen: boolean;
}> {
  let allGreen = true;
  const title = 'RFC7515#Appendix1 Examples';
  let log = '';
  for (const d of data) {
    log += d.title + '\n';
    const jws = await JWS.produce(d.input.alg, d.input.jwks, d.input.message, d.input.options);
    if (d.reproducible) {
      log += 'テストには再現性があるため、シリアライズした結果を比較する\n';
      if (d.output.compact) {
        const compact = jws.serialize('compact');
        const same = d.output.compact === compact;
        allGreen &&= same;
        log += 'Compact: ' + (same ? '(OK) ' : 'X ');
      }
      if (d.output.json) {
        const json = jws.serialize('json');
        const same = JWSJSONSerializer.equals(d.output.json, json);
        allGreen &&= same;
        log += 'JSON: ' + (same ? '(OK) ' : 'X ');
      }
    }
    log += 'JWS の検証する\n';
    const verifyKeys: JWKSet = {
      keys: d.input.jwks.keys.map((k) => {
        if (isJWK(k, 'Priv')) return exportPubJWK(k);
        if (isJWK(k, 'Pub')) return k;
        throw TypeError(`JWK ではない鍵が紛れ込んでいる ${k}`);
      }),
    };
    const valid = await jws.validate(verifyKeys);
    allGreen &&= valid;
    log += 'Produce and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
    if (d.output.compact) {
      const jws = JWS.deserialize(d.output.compact);
      const valid = await jws.validate(verifyKeys);
      allGreen &&= valid;
      log += 'Deserialize Compact and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
    }
    if (d.output.json) {
      const jws = JWS.deserialize(d.output.json);
      const valid = await jws.validate(verifyKeys);
      allGreen &&= valid;
      log += 'Deserialize JSON and Validate JWS' + (valid ? '(OK) ' : 'X ') + '\n';
    }
  }
  return { title, allGreen, log };
}

const data: Array<{
  title: string;
  reproducible?: boolean;
  input: {
    alg: Parameters<typeof JWS.produce>[0];
    jwks: Parameters<typeof JWS.produce>[1];
    message: Parameters<typeof JWS.produce>[2];
    options: Parameters<typeof JWS.produce>[3];
  };
  output: {
    compact?: string;
    json?: JWSJSONSerialization;
  };
}> = [
  {
    title: 'A.1.  Example JWS Using HMAC SHA-256',
    reproducible: true,
    input: {
      alg: 'HS256',
      jwks: {
        keys: [
          {
            kty: 'oct',
            k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
          },
        ],
      },
      message: new Uint8Array([
        123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
        34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
        47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111,
        116, 34, 58, 116, 114, 117, 101, 125,
      ]) as JWSPayload,
      options: {
        header: {
          p: {
            initialValue: { typ: 'JWT', alg: 'HS256' } as JWSProtectedHeader,
            b64u: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
          },
        },
      },
    },
    output: {
      compact:
        'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    },
  },
  {
    title: 'A.2.  Example JWS Using RSASSA-PKCS1-v1_5 SHA-256',
    reproducible: true,
    input: {
      alg: 'RS256',
      jwks: {
        keys: [
          {
            kty: 'RSA',
            n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            e: 'AQAB',
            d: 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            p: '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            q: 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            dp: 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            dq: 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            qi: 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
          } as JWK<'RSA', 'Priv'>,
        ],
      },
      message: new Uint8Array([
        123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
        34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
        47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111,
        116, 34, 58, 116, 114, 117, 101, 125,
      ]) as JWSPayload,
      options: {
        header: {
          p: {
            b64u: 'eyJhbGciOiJSUzI1NiJ9',
          },
        },
      },
    },
    output: {
      compact:
        'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw',
    },
  },
  {
    title: 'A.3.  Example JWS Using ECDSA P-256 SHA-256',
    reproducible: false,
    input: {
      alg: 'ES256',
      jwks: {
        keys: [
          {
            kty: 'EC',
            crv: 'P-256',
            x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
          } as JWK<'EC', 'Priv'>,
        ],
      },
      message: new Uint8Array([
        123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
        34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
        47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111,
        116, 34, 58, 116, 114, 117, 101, 125,
      ]) as JWSPayload,
      options: {
        header: {
          p: { b64u: 'eyJhbGciOiJFUzI1NiJ9' },
        },
      },
    },
    output: {
      compact:
        'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
    },
  },
  {
    title: 'A.4.  Example JWS Using ECDSA P-521 SHA-512',
    input: {
      alg: 'ES512',
      jwks: {
        keys: [
          {
            kty: 'EC',
            crv: 'P-521',
            x: 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
            y: 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
            d: 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
          } as JWK<'EC', 'Priv'>,
        ],
      },
      message: new Uint8Array([80, 97, 121, 108, 111, 97, 100]) as JWSPayload,
      options: {
        header: {
          p: { b64u: 'eyJhbGciOiJFUzUxMiJ9' },
        },
      },
    },
    output: {
      compact:
        'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn',
    },
  },
  {
    title: 'A.5.  Example Unsecured JWS',
    reproducible: true,
    input: {
      alg: 'none',
      jwks: { keys: [] },
      message: new Uint8Array([
        123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
        34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
        47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111,
        116, 34, 58, 116, 114, 117, 101, 125,
      ]) as JWSPayload,
      options: {
        header: {
          p: { b64u: 'eyJhbGciOiJub25lIn0' },
        },
      },
    },
    output: {
      compact:
        'eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.',
    },
  },
  {
    title: 'A.6.  Example JWS Using General JWS JSON Serialization',
    input: {
      alg: ['RS256', 'ES256'],
      jwks: {
        keys: [
          {
            kty: 'RSA',
            n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            e: 'AQAB',
            d: 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            p: '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            q: 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            dp: 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            dq: 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            qi: 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
          } as JWK<'RSA', 'Priv'>,
          {
            kty: 'EC',
            crv: 'P-256',
            x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
          } as JWK<'EC', 'Priv'>,
        ],
      },
      message: new Uint8Array([
        123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
        34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
        47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111,
        116, 34, 58, 116, 114, 117, 101, 125,
      ]) as JWSPayload,
      options: {
        header: [
          {
            p: {
              initialValue: { alg: 'RS256' } as JWSProtectedHeader,
              b64u: 'eyJhbGciOiJSUzI1NiJ9',
            },
            u: {
              initialValue: { kid: '2010-12-29' } as JWSUnprotectedHeader,
            },
          },
          {
            p: {
              initialValue: { alg: 'ES256' } as JWSProtectedHeader,
              b64u: 'eyJhbGciOiJFUzI1NiJ9',
            },
            u: {
              initialValue: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' } as JWSUnprotectedHeader,
            },
          },
        ],
      },
    },
    output: {
      json: {
        payload:
          'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
        signatures: [
          {
            protected: 'eyJhbGciOiJSUzI1NiJ9',
            header: { kid: '2010-12-29' } as JWSUnprotectedHeader,
            signature:
              'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw',
          },
          {
            protected: 'eyJhbGciOiJFUzI1NiJ9',
            header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' } as JWSUnprotectedHeader,
            signature:
              'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
          },
        ],
      },
    },
  },
];
