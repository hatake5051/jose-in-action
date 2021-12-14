import { JWE } from './internal/jwe';
import {
  JWECompactSerialization,
  JWEFlattenedJSONSerialization,
  JWEFlattenedJSONSerializer,
  JWEJSONSerialization,
  JWEJSONSerializer,
} from './internal/serialize';

export { JWECompactSerialization, JWEJSONSerialization, JWEFlattenedJSONSerialization, JWE };

export const isJWEJSONSerialization = JWEJSONSerializer.is;
export const equalsJWEJSONSerialization = JWEJSONSerializer.equals;
export const isJWEFlattenedJSONSerialization = JWEFlattenedJSONSerializer.is;
export const equalsJWEFlattenedJSONSerialization = JWEFlattenedJSONSerializer.equals;
