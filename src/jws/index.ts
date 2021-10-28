import {
  equalsJWSJOSEHeader,
  isJWSProtectedHeader,
  isJWSUnprotectedHeader,
  JWSProtectedHeader,
  JWSUnprotectedHeader,
} from './internal/header';
import { JWS } from './internal/jws';
import { MACOperator } from './internal/mac';
import {
  isJWSFlattenedJSONSerialization,
  isJWSJSONSerialization,
  JWSCompactSerialization,
  JWSFlattenedJSONSerialization,
  JWSJSONSerialization,
} from './internal/serialize';
import { SigOperator } from './internal/sig';
import { JWSSignature } from './internal/types';

export {
  JWS,
  JWSProtectedHeader,
  isJWSProtectedHeader,
  JWSUnprotectedHeader,
  isJWSUnprotectedHeader,
  equalsJWSJOSEHeader,
  JWSSignature,
  JWSCompactSerialization,
  JWSJSONSerialization,
  JWSFlattenedJSONSerialization,
  isJWSJSONSerialization,
  isJWSFlattenedJSONSerialization,
  SigOperator,
  MACOperator,
};
