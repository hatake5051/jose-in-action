// --------------------BEGIN entry point --------------------

import { test as jwktest } from 'jwk/test/rfc7517-a.test';
import { test as x5ctest } from 'jwk/test/rfc7517-b.test';
import { test as ectest } from 'jwk/test/rfc7520-ec.test';
import { test as octtest } from 'jwk/test/rfc7520-oct.test';
import { test as rsatest } from 'jwk/test/rfc7520-rsa.test';
import { paths as jwspaths } from 'jws/test/rfc7520.4.test';
import { test as jwstest } from 'jws/test/rfc7520.test';

window.document.getElementById('jwk')?.addEventListener('click', test_jwk);
window.document.getElementById('jws')?.addEventListener('click', test_jws);

async function test_jwk() {
  console.group('JWK のテストを始めます');
  const logs = await Promise.all(
    [jwktest, x5ctest, ectest, octtest, rsatest].map(async (test) => await test())
  );
  let allAllGreen = true;
  logs.forEach(({ title, log, allGreen }) => {
    allAllGreen = allGreen;
    console.group(title, allGreen);
    console.log(log);
    console.groupEnd();
  });
  console.log('JWK のテスト終了', allAllGreen);
  console.groupEnd();
}

async function test_jws() {
  console.group('JWS のテストを始めます');
  const logs = await Promise.all(jwspaths.map(async (path) => await jwstest(path)));
  let allAllGreen = true;
  logs.forEach(({ title, log, allGreen }) => {
    allAllGreen = allGreen;
    console.group(title, allGreen);
    console.log(log);
    console.groupEnd();
  });
  console.log('JWS のテスト終了', allAllGreen);
  console.groupEnd();
}

// --------------------END entry point --------------------
