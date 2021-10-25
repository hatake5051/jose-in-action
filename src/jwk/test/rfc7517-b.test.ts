// --------------------BEGIN RFC7517 appendix.B test --------------------

import { isJWK, isJWKSet, validJWK } from '../index';
import { parseX509BASE64EncodedDER, validateSelfSignedCert } from '../internal/x509';

export { test };

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
    log += 'X509証明書(RSA) OK ';
  } else {
    log += 'X509証明書(RSA) X ';
    allGreen = false;
  }
  const eccert = parseX509BASE64EncodedDER(amazon_root_ca_3.x5c[0]);
  const isECVerified = await validateSelfSignedCert(eccert);
  if (isECVerified) {
    log += 'X509証明書(EC) OK\n';
  } else {
    log += 'X509証明書(EC) X\n';
    allGreen = false;
  }

  log += 'TEST NAME: Validate JWK.x5c\n';
  if (isJWK(b, 'RSA', 'Pub')) {
    if (await validJWK(b, { x5c: { selfSigned: true } })) {
      log += 'JWK.x5c (RSA) の検証と整合性の確認に成功\n';
    } else {
      log += 'JWK.x5c (RSA) の検証に失敗\n';
      allGreen = false;
    }
  } else {
    log += 'JWK<RSA,Pub> のパースに失敗\n';
    allGreen = false;
  }
  if (isJWK(amazon_root_ca_3, 'EC', 'Pub')) {
    if (await validJWK(amazon_root_ca_3, { x5c: { selfSigned: true } })) {
      log += 'JWK.x5c (EC) の検証と整合性の確認に成功\n';
    } else {
      log += 'JWK.x5c (EC) の検証に失敗\n';
      allGreen = false;
    }
  } else {
    log += 'JWK<EC, Pub> のパースに失敗\n';
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
      if (isJWK(key, 'RSA', 'Pub')) {
        if (await validJWK(key, { x5c: { selfSigned: true } })) {
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

// ref: https://good.sca3a.amazontrust.com/ に基づいて JWK を生成した
const amazon_root_ca_3 = {
  kty: 'EC',
  crv: 'P-256',
  x: 'KZenxkF_wA2b6AEbVsbyUqW6LbIS6NIu1_rJxdiqbR8',
  y: 'c4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt4',
  x5c: [
    'MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKlui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6jQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSrttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkrBqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteMYyRIHN8wfdVoOw==',
  ],
};

// --------------------END RFC7517 appendix.B test --------------------
