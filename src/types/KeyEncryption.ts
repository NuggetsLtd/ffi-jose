export enum KeyEncryption {
  // Direct encryption
  Dir,
  // Diffie-Hellman
  EcdhEs,
  EcdhEsA128kw,
  EcdhEsA192kw,
  EcdhEsA256kw,
  // RSAES
  Rsa1_5,
  RsaOaep,
  RsaOaep256,
  RsaOaep384,
  RsaOaep512,
  // PBES2
  Pbes2Hs256A128kw,
  Pbes2Hs384A192kw,
  Pbes2Hs512A256kw,
  // AES Key Wrap
  A128kw,
  A192kw,
  A256kw,
  // AES GCM Key wrap
  A128gcmkw,
  A192gcmkw,
  A256gcmkw,
}
