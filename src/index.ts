import { test } from './jwk/ec.test';

// ------------------------------------ entry point
(async () => {
  const { log, allGreen } = await test();
  console.log(allGreen);
  console.log(log);
})();
