export interface JoseEncryptResponse {
  readonly ciphertext: Uint8Array;
  tag?: Uint8Array;
}
