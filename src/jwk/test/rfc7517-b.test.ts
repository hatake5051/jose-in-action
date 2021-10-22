import { isJWKPub, isJWKSet, validX5CinJWKPub } from '../index';
import {
  parseX509BASE64EncodedDER,
  validateSelfSignedCert,
} from '../internal/x509';

async function test(): Promise<{
  title: string;
  log: string;
  allGreen: boolean;
}> {
  let allGreen = true;
  const title = 'RFC7517#B.Example Use of "x5c" Parameter;';
  let log = 'TEST NAME: Self Signed Certificate Verification: ';
  const cert = parseX509BASE64EncodedDER(b.x5c[0]);
  const isVerified = await validateSelfSignedCert(cert);
  if (isVerified) {
    log += 'X509証明書のパースと検証に成功\n';
  } else {
    log += 'X509証明書のパースと検証に失敗\n';
    allGreen = false;
  }

  log += 'TEST NAME: Validate JWK.x5c: ';
  if (isJWKPub('RSA', b)) {
    if (await validX5CinJWKPub(b)) {
      log += 'JWK.x5c の検証と整合性の確認に成功\n';
    } else {
      log += 'JWK.x5c の検証に失敗\n';
      allGreen = false;
    }
  } else {
    log += 'JWKPub<RSA> のパースに失敗\n';
    allGreen = false;
  }

  log += "TEST NAME: Validate JWK.x5c of microsoft's JWKSet for oidc: ";
  const data = await (
    await fetch('https://login.microsoftonline.com/common/discovery/v2.0/keys')
  ).json();
  if (!isJWKSet(data)) {
    log += 'JWKSet の取得に失敗\n';
    allGreen = false;
  } else {
    for (const key of data.keys) {
      if (isJWKPub('RSA', key)) {
        if (await validX5CinJWKPub(key)) {
          log += 'JWK.x5c の検証と整合性の確認に成功\n';
        } else {
          log += 'JWK.x5c の検証に失敗\n';
          allGreen = false;
        }
      } else {
        log += 'MSから取得する鍵は全て RSA 公開鍵のはず\n';
        allGreen = false;
      }
    }
  }

  return { title, log, allGreen };
}

export { test };

const b = {
  kty: 'RSA',
  use: 'sig',
  kid: '1b94c',
  n: 'vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ',
  e: 'AQAB',
  x5c: [
    'MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==',
  ],
};
