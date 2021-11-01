import {
  equalsJWSJOSEHeader,
  isJWSProtectedHeader,
  isJWSUnprotectedHeader,
  JWSJOSEHeader,
  JWSProtectedHeader,
  JWSUnprotectedHeader,
} from './internal/header';
import { JWS } from './internal/jws';
import { MACOperator } from './internal/mac';
import {
  equalsJWSFlattenedJSONSerialization,
  equalsJWSJSONSerialization,
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
  JWSJOSEHeader,
  equalsJWSJOSEHeader,
  JWSSignature,
  JWSCompactSerialization,
  JWSJSONSerialization,
  JWSFlattenedJSONSerialization,
  isJWSJSONSerialization,
  isJWSFlattenedJSONSerialization,
  equalsJWSJSONSerialization,
  equalsJWSFlattenedJSONSerialization,
  SigOperator,
  MACOperator,
};
