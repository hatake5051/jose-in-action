// --------------------BEGIN entry point --------------------

import { test as jwktest } from './jwk/test/rfc7517-a.test';
import { test as x5ctest } from './jwk/test/rfc7517-b.test';
import { test as ectest } from './jwk/test/rfc7520-ec.test';
import { test as octtest } from './jwk/test/rfc7520-oct.test';
import { test as rsatest } from './jwk/test/rfc7520-rsa.test';
import { sec4 } from './jws/test/rfc7520.test';

window.document.getElementById('jwk')?.addEventListener('click', test_jwk);

async function test_jwk() {
  for (const test of [jwktest, x5ctest, ectest, octtest, rsatest]) {
    const { title, log, allGreen } = await test();
    console.group(title, allGreen);
    console.log(log);
    console.groupEnd();
  }
}

sec4();

// --------------------END entry point --------------------
