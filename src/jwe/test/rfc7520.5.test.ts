import { Alg, EncAlg, isAlg, isEncAlg } from 'iana/alg';
import { isJOSEHeader } from 'iana/header';
import { JWEFlattenedJSONSerializer, JWEJSONSerializer } from 'jwe';
import {
  JWECompactSerialization,
  JWEFlattenedJSONSerialization,
  JWEJSONSerialization,
  JWEPerRecipientUnprotectedHeader,
  JWEProtectedHeader,
  JWESharedUnprotectedHeader,
} from 'jwe/type';
import { isJWK, JWK } from 'jwk';
import { Arrayable, Flatten, isArrayable, isObject } from 'utility';

export { fetchData, paths };

const paths = [
  '5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json',
  '5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json',
  '5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json',
  '5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json',
  '5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json',
  '5_6.direct_encryption_using_aes-gcm.json',
  '5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json',
  '5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json',
  // '5_9.compressed_content.json',
  '5_10.including_additional_authentication_data.json',
  '5_11.protecting_specific_header_fields.json',
  '5_12.protecting_content_only.json',
  '5_13.encrypting_to_multiple_recipients.json',
] as const;

const baseURL = 'https://raw.githubusercontent.com/ietf-jose/cookbook/master/jwe/';

async function fetchData(path: string): Promise<Data> {
  const resp = await fetch(baseURL + path);
  const data = await resp.json();
  // examples のミスを治す
  if (path === '5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json') {
    // rfc7516#7.2.1 によると recipients は 空オブジェクトでも recipient ごとにいるはずだが...
    data.output.json.recipients = [{}];
  }
  if (path === '5_6.direct_encryption_using_aes-gcm.json') {
    // rfc7516#7.2.1 によると recipients は 空オブジェクトでも recipient ごとにいるはずだが...
    data.output.json.recipients = [{}];
  }
  if (path === '5_13.encrypting_to_multiple_recipients.json') {
    // タイポ
    data.input.enc = 'A128CBC-HS256';
  }

  if (!isData(data)) {
    throw new EvalError('テストデータの取得に失敗');
  }
  return data;
}

type Data = {
  title: string;
  reproducible?: boolean;
  input: {
    plaintext: string;
    key?: Arrayable<JWK>;
    pwd?: string;
    alg: Arrayable<Alg<'JWE'>>;
    enc: EncAlg;
    aad?: string;
  };
  generated: {
    cek?: string;
    iv: string;
  };
  encrypting_key?: Arrayable<{
    header?: JWEPerRecipientUnprotectedHeader;
    epk?: JWK<'EC', 'Priv'>;
  }>;
  encrypting_content: {
    protected?: JWEProtectedHeader;
    protected_b64u?: string;
    unprotected?: JWESharedUnprotectedHeader;
  };
  output: {
    compact?: JWECompactSerialization;
    json: JWEJSONSerialization;
    json_flat?: JWEFlattenedJSONSerialization;
  };
};

const isData = (arg: unknown): arg is Data =>
  isObject<Data>(arg) &&
  typeof arg.title === 'string' &&
  (arg.reproducible == null || typeof arg.reproducible === 'boolean') &&
  isObject<Data['input']>(arg.input) &&
  typeof arg.input.plaintext === 'string' &&
  (arg.input.key == null || isArrayable<JWK>(arg.input.key, (k): k is JWK => isJWK(k))) &&
  (arg.input.pwd == null || typeof arg.input.pwd === 'string') &&
  isArrayable<Alg<'JWE'>>(arg.input.alg, (u: unknown): u is Alg<'JWE'> => isAlg(u, 'JWE')) &&
  isEncAlg(arg.input.enc) &&
  (arg.input.aad == null || typeof arg.input.aad === 'string') &&
  isObject<Data['generated']>(arg.generated) &&
  (arg.generated.cek == null || typeof arg.generated.cek === 'string') &&
  typeof arg.generated.iv === 'string' &&
  (arg.encrypting_key == null ||
    isArrayable<Flatten<NonNullable<Data['encrypting_key']>>>(
      arg.encrypting_key,
      (u): u is Flatten<NonNullable<Data['encrypting_key']>> =>
        isObject<Flatten<NonNullable<Data['encrypting_key']>>>(u) &&
        (u.header == null || isJOSEHeader(u.header, 'JWE')) &&
        (u.epk == null || isJWK(u.epk, 'EC', 'Priv'))
    )) &&
  isObject<Data['encrypting_content']>(arg.encrypting_content) &&
  (arg.encrypting_content.protected == null ||
    isJOSEHeader(arg.encrypting_content.protected, 'JWE')) &&
  (arg.encrypting_content.protected_b64u == null ||
    typeof arg.encrypting_content.protected_b64u === 'string') &&
  (arg.encrypting_content.unprotected == null ||
    isJOSEHeader(arg.encrypting_content.unprotected, 'JWE')) &&
  isObject<Data['output']>(arg.output) &&
  (arg.output.compact == null || typeof arg.output.compact === 'string') &&
  JWEJSONSerializer.is(arg.output.json) &&
  (arg.output.json_flat == null || JWEFlattenedJSONSerializer.is(arg.output.json_flat));
