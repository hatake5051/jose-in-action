// --------------------BEGIN JWK common parameters --------------------

import { Kty } from '../../iana';

export { CommomJWKParams, isCommonJWKParams };

/**
 * JWK が持つ共通パラメータを表す。
 */
type CommomJWKParams<K extends Kty> = {
  // TODO: パラメータを RFC7517 Section.4 に基づいて実装する
};

/**
 * 共通パラメータのうち JWK として必須なものを引数が持っているか確認する。
 */
const isCommonJWKParams = (arg: unknown): arg is CommomJWKParams<Kty> => {
  // TODO: JWK 共通パラメータで必須なものが存在するかチェックする
  return false;
};

// --------------------END JWK common parameters --------------------
