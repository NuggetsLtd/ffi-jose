
export interface JWK {
  readonly kty?: "EC" | "OKP";
  readonly crv: "P-256" | "P-384" | "P-521" | "secp256k1" | "Ed25519" | "Ed448" | "X25519" | "X448";
  readonly d?: string;
  readonly dp?: string;
  readonly dq?: string;
  readonly e?: string;
  readonly k?: string;
  readonly n?: string;
  readonly p?: string;
  readonly q?: string;
  readonly qi?: string;
  readonly x?: string;
  readonly y?: string;
  readonly use?: "sig" | "enc";
}
