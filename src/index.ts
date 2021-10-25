// --------------------BEGIN entry point --------------------

import { test as ectest } from './jwk/test/rfc7520-ec.test';
import { test as octtest } from './jwk/test/rfc7520-oct.test';
import { test as rsatest } from './jwk/test/rfc7520-rsa.test';

(async () => {
  for (const test of [ectest, octtest, rsatest]) {
    const { title, log, allGreen } = await test();
    console.group(title, allGreen);
    console.log(log);
    console.groupEnd();
  }
})();

// --------------------END entry point --------------------
