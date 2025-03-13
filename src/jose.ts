import type {
  JoseGenerateJwkRequest,
  JoseGenerateKeyPairResponse,
  JoseEncryptResponse,
  JWK,
  JoseModule,
} from "./types/index.js";
import { NamedCurve, ContentEncryption, KeyEncryption, SigningAlgorithm } from "./types/index.js";
import { PrivateKeyObject, PublicKeyObject } from "./KeyObject.js";

import { createRequire } from "node:module";
const jose: JoseModule = createRequire(import.meta.url)("../native/index.node");

export const generateJWK = async (request: JoseGenerateJwkRequest): Promise<JWK> => {
  const { namedCurve } = request;
  let jwkString;

  try {
    jwkString = jose.generate_key_pair_jwk({ namedCurve });
  } catch (error: any) {
    if (error.message === "internal error in Neon module: Unknown curve") {
      throw new TypeError("Unknown curve");
    }

    throw error;
  }

  return JSON.parse(jwkString);
};

export const generateKeyPair = async (
  type: string,
  options?: { namedCurve: string }
): Promise<{ publicKey: PublicKeyObject; privateKey: PrivateKeyObject }> => {
  let crv;
  let keyPairString;

  switch (type) {
    case "ec":
      crv = options?.namedCurve || "";
      break;
    case "ed25519":
    case "ed448":
    case "x25519":
    case "x448":
      crv = type;
      break;
    default:
      throw new TypeError('Invalid or unsupported "type" Parameter value');
  }

  const crv_mapped = {
    "P-256": NamedCurve.P256,
    "P-384": NamedCurve.P384,
    "P-521": NamedCurve.P521,
    secp256k1: NamedCurve.Secp256k1,
    ed25519: NamedCurve.Ed25519,
    ed448: NamedCurve.Ed448,
    x25519: NamedCurve.X25519,
    x448: NamedCurve.X448,
  }[crv];

  if (crv_mapped === undefined) {
    throw new TypeError('Invalid or unsupported "crv" value');
  }

  try {
    keyPairString = jose.generate_key_pair_jwk({ namedCurve: crv_mapped });
  } catch (error: any) {
    if (error.message === "internal error in Neon module: Unknown curve") {
      throw new TypeError("Unknown curve");
    }

    throw error;
  }

  const keyPair: JoseGenerateKeyPairResponse = JSON.parse(keyPairString);

  return {
    privateKey: new PrivateKeyObject(keyPair, type, options?.namedCurve),
    publicKey: new PublicKeyObject(keyPair, type, options?.namedCurve),
  };
};

export const encrypt = async (
  enc: string,
  plaintext: Uint8Array,
  cek: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  didcomm: boolean = false
): Promise<JoseEncryptResponse> => {
  let encryptedObj;
  const enc_mapped = {
    A128GCM: ContentEncryption.A128gcm,
    A192GCM: ContentEncryption.A192gcm,
    A256GCM: ContentEncryption.A256gcm,
    "A128CBC-HS256": ContentEncryption.A128cbcHs256,
    "A192CBC-HS384": ContentEncryption.A192cbcHs384,
    "A256CBC-HS512": ContentEncryption.A256cbcHs512,
  }[enc];

  if (enc_mapped === undefined) {
    throw new TypeError(`Invalid or unsupported "enc" value: "${enc}"`);
  }

  try {
    encryptedObj = jose.encrypt(enc_mapped, cek.buffer, iv.buffer, plaintext.buffer, aad.buffer, didcomm);
  } catch (error: any) {
    if (error.message === "internal error in Neon module: Unknown curve") {
      throw new TypeError("Unknown curve");
    }

    throw error;
  }

  const { ciphertext, tag } = encryptedObj;

  const returnObject: JoseEncryptResponse = {
    ciphertext: Uint8Array.from(Buffer.from(ciphertext, "base64")),
  };

  if (tag) {
    returnObject.tag = Uint8Array.from(Buffer.from(tag, "base64"));
  }

  return returnObject;
};

export const decrypt = async (
  enc: string,
  cek: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> => {
  let decrypted;

  const enc_mapped = {
    A128GCM: ContentEncryption.A128gcm,
    A192GCM: ContentEncryption.A192gcm,
    A256GCM: ContentEncryption.A256gcm,
    "A128CBC-HS256": ContentEncryption.A128cbcHs256,
    "A192CBC-HS384": ContentEncryption.A192cbcHs384,
    "A256CBC-HS512": ContentEncryption.A256cbcHs512,
  }[enc];

  if (enc_mapped === undefined) {
    throw new TypeError(`Invalid or unsupported "enc" value: "${enc}"`);
  }

  try {
    decrypted = jose.decrypt(enc_mapped, cek.buffer, ciphertext.buffer, iv.buffer, tag.buffer, aad.buffer);
  } catch (error: any) {
    if (error.message === "internal error in Neon module: Unknown curve") {
      throw new TypeError("Unknown curve");
    }

    throw error;
  }

  return Uint8Array.from(Buffer.from(decrypted, "base64"));
};

const _isJsonString = (str: string) => {
  try {
    JSON.parse(str);
  } catch (e) {
    return false;
  }
  return true;
};

const _jsonConvertToString = (data: any) => {
  // ensure data is serialised as JSON string
  const dataSerialised = typeof data === "string" && _isJsonString(data) ? data : JSON.stringify(data);

  return dataSerialised;
};

export const generalEncryptJson = async (
  alg: KeyEncryption,
  enc: ContentEncryption,
  payload: any,
  recipients: JWK[],
  didcomm: boolean = false
): Promise<any> => {
  recipients.forEach((recipient) => {
    if (!recipient?.kid) {
      throw new Error("Recipient JWKs must contain key identifier (kid)");
    }
  });

  let jwe_string = jose.general_encrypt_json(
    alg,
    enc,
    _jsonConvertToString(payload),
    _jsonConvertToString(recipients),
    didcomm
  );

  return JSON.parse(jwe_string);
};

export const decryptJson = async (jwe: any, jwk: JWK): Promise<any> => {
  let json_string = jose.decrypt_json(_jsonConvertToString(jwe), _jsonConvertToString(jwk));

  return JSON.parse(json_string);
};

export const compactSignJson = async (
  alg: SigningAlgorithm,
  payload: any,
  jwk: JWK,
  didcomm: boolean = false
): Promise<any> => {
  return jose.compact_sign_json(alg, _jsonConvertToString(payload), _jsonConvertToString(jwk), didcomm);
};

export const compactJsonVerify = async (jws: string, jwk: JWK): Promise<any> => {
  let json_string = jose.compact_json_verify(jws, _jsonConvertToString(jwk));

  return JSON.parse(json_string);
};

export const flattenedSignJson = async (
  alg: SigningAlgorithm,
  payload: any,
  jwk: JWK,
  didcomm: boolean = false
): Promise<any> => {
  if (!jwk.kid) {
    throw new Error('JWK `kid` property required for "flattened" signing');
  }

  let json_string = jose.flattened_sign_json(alg, _jsonConvertToString(payload), _jsonConvertToString(jwk), didcomm);

  return JSON.parse(json_string);
};

export const jsonVerify = async (jws: any, jwk: JWK): Promise<any> => {
  let json_string = jose.json_verify(_jsonConvertToString(jws), _jsonConvertToString(jwk));

  return JSON.parse(json_string);
};

export const generalSignJson = async (payload: any, jwks: [JWK], didcomm: boolean = false): Promise<any> => {
  jwks.forEach((jwk) => {
    if (!jwk.kid) {
      throw new Error('JWK `kid` property required for "general" signing');
    }
  });

  let json_string = jose.general_sign_json(_jsonConvertToString(payload), _jsonConvertToString(jwks), didcomm);

  return JSON.parse(json_string);
};
