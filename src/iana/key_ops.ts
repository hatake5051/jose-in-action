export { KeyUse, isKeyUse, KeyOps, isKeyOps };

/**
 * KeyUse は JSON Web Key Use を列挙する。
 */
type KeyUse = typeof keyUseList[number];
const keyUseList = ['sig', 'enc'] as const;
const isKeyUse = (arg: unknown): arg is KeyUse =>
  typeof arg === 'string' && keyUseList.some((u) => u === arg);

/**
 * JSON Web Key Operations を列挙する。
 */
type KeyOps = typeof keyOpsList[number];
const keyOpsList = [
  'sign',
  'verify',
  'encrypt',
  'decrypt',
  'wrapKey',
  'unwrapKey',
  'deriveKey',
  'deriveBits',
] as const;
const isKeyOps = (arg: unknown): arg is KeyOps =>
  typeof arg === 'string' && keyOpsList.some((u) => u === arg);
