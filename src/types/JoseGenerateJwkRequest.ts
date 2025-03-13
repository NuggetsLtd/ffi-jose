import type { NamedCurve } from "./NamedCurve.js";

export interface JoseGenerateJwkRequest {
  readonly namedCurve: NamedCurve;
}
