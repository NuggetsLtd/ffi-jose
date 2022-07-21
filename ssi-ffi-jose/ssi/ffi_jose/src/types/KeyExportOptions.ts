export interface SymmetricKeyExportOptions {
  readonly format: "buffer" | "jwk";
}

export interface PublicKeyExportOptions {
  readonly type: "pkcs1" | "spki";
  readonly format: "pem" | "der" | "jwk";
}

export interface PrivateKeyExportOptions {
  readonly type: "pkcs1" | "pksc8" | "sec1";
  readonly format: "pem" | "der" | "jwk";
  readonly cipher?: string;
  readonly passphrase?: string;
}
