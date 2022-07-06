export interface JoseEncryptResponse {
  readonly ciphertext: Uint8Array,
  readonly tag?: Uint8Array,
}
