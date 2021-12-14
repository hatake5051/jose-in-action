import { JWE } from './internal/jwe';
import { JWEFlattenedJSONSerializer, JWEJSONSerializer } from './internal/serialize';

export { JWE };

export const isJWEJSONSerialization = JWEJSONSerializer.is;
export const equalsJWEJSONSerialization = JWEJSONSerializer.equals;
export const isJWEFlattenedJSONSerialization = JWEFlattenedJSONSerializer.is;
export const equalsJWEFlattenedJSONSerialization = JWEFlattenedJSONSerializer.equals;
