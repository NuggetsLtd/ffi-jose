import type { NamedCurve } from "./NamedCurve";

export interface JoseGenerateJwkRequest {
  readonly namedCurve: NamedCurve;
}
