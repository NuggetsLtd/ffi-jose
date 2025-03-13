import type { PublicKeyExportOptions, PrivateKeyExportOptions, JoseGenerateKeyPairResponse } from "./types/index.js";

const kKeyType = Symbol("kKeyType");

export class KeyObject {
  [kKeyType]: any;
  _keyPair: JoseGenerateKeyPairResponse;

  constructor(type: string, keyPair: JoseGenerateKeyPairResponse) {
    if (type !== "secret" && type !== "public" && type !== "private") {
      throw new TypeError(`The 'type' is invalid. Received ${type}`);
    }

    this[kKeyType] = type;
    this._keyPair = keyPair;

    Object.defineProperty(this, "_keyPair", {
      enumerable: false,
      configurable: false,
      writable: false,
    });
  }

  get type() {
    return this[kKeyType];
  }
}

const kAsymmetricKeyType = Symbol("kAsymmetricKeyType");
const kAsymmetricKeyDetails = Symbol("kAsymmetricKeyDetails");

class AsymmetricKeyObject extends KeyObject {
  [kAsymmetricKeyType]: any;
  [kAsymmetricKeyDetails]: any;

  constructor(
    visibility: string,
    keyPair: JoseGenerateKeyPairResponse,
    { type, namedCurve }: { type: string; namedCurve?: string }
  ) {
    super(visibility, keyPair);

    this[kAsymmetricKeyType] = type;
    this[kAsymmetricKeyDetails] = namedCurve;
  }

  get asymmetricKeyType() {
    return this[kAsymmetricKeyType];
  }

  get asymmetricKeyDetails() {
    switch (this.asymmetricKeyType) {
      case "rsa":
      case "rsa-pss":
      case "dsa":
      case "ec":
        return this[kAsymmetricKeyDetails] || {};
      default:
        return {};
    }
  }
}

export class PublicKeyObject extends AsymmetricKeyObject {
  constructor(keyPair: JoseGenerateKeyPairResponse, type: string, namedCurve?: string) {
    super("public", keyPair, { type, namedCurve });
  }

  export(options: PublicKeyExportOptions) {
    if (options && options.format === "jwk") {
      return this._keyPair.jwk_public_key;
    }
    if (options && options.format === "der") {
      return Buffer.from(this._keyPair.der_public_key, "base64");
    }
    if (options && options.format === "pem") {
      return Buffer.from(this._keyPair.pem_public_key, "base64");
    }
    return this._keyPair.jwk_public_key;
  }
}

export class PrivateKeyObject extends AsymmetricKeyObject {
  constructor(keyPair: JoseGenerateKeyPairResponse, type: string, namedCurve?: string) {
    super("private", keyPair, { type, namedCurve });
  }

  export(options: PrivateKeyExportOptions) {
    if (options && options.format === "jwk") {
      return this._keyPair.jwk_private_key;
    }
    if (options && options.format === "der") {
      return Buffer.from(this._keyPair.der_private_key, "base64");
    }
    if (options && options.format === "pem") {
      return Buffer.from(this._keyPair.pem_private_key, "base64");
    }
    return this._keyPair.jwk_private_key;
  }
}
