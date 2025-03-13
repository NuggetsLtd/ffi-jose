import type { JWK } from "./JWK.js";

export interface JoseGenerateKeyPairResponse {
  readonly der_private_key: string;
  readonly der_public_key: string;
  readonly jwk_key_pair: JWK;
  readonly jwk_private_key: JWK;
  readonly jwk_public_key: JWK;
  readonly pem_private_key: string;
  readonly pem_public_key: string;
}
