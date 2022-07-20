import type {
  JoseGenerateJwkRequest,
  JoseGenerateKeyPairResponse,
  JoseEncryptResponse,
  JWK,
} from "./types"
import {
  NamedCurve,
  ContentEncryption,
} from "./types"
import {
  PrivateKeyObject,
  PublicKeyObject
} from "./KeyObject";

/**
 * @ignore
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const jose = require(path.resolve(path.join(__dirname, "../native/index.node")));

const _castToUint8Array = (value: Iterable<number>) => {
  if(value instanceof Uint8Array) {
    return Uint8Array.from(value)
  }
  
  throw new Error('Unable to convert value to Uint8Array')
}

export const generateJWK = async (request: JoseGenerateJwkRequest): Promise<JWK> => {
  const { namedCurve } = request
  let jwkString

  try {
    jwkString = await jose.generate_key_pair_jwk({ namedCurve })
  } catch (error: any) {
    if(error.message === 'internal error in Neon module: Unknown curve') {
      throw new TypeError('Unknown curve')
    }

    throw error
  }
  
  return JSON.parse(jwkString)
}

export const generateKeyPair = async (type: string, options?: { namedCurve: string }): Promise<{ publicKey: PublicKeyObject, privateKey: PrivateKeyObject }> => {
  let crv
  let keyPairString

  switch (type) {
    case 'ec':
      crv = options?.namedCurve || ""
      break;
    case 'ed25519':
    case 'ed448':
    case 'x25519':
    case 'x448':
      crv = type
      break;
    default:
      throw new TypeError('Invalid or unsupported "type" Parameter value')
  }

  const crv_mapped = {
    'P-256': NamedCurve.P256,
    'P-384': NamedCurve.P384,
    'P-521': NamedCurve.P521,
    'secp256k1': NamedCurve.Secp256k1,
    'ed25519': NamedCurve.Ed25519,
    'ed448': NamedCurve.Ed448,
    'x25519': NamedCurve.X25519,
    'x448': NamedCurve.X448,
  }[crv]

  if(crv_mapped === undefined) {
    throw new TypeError('Invalid or unsupported "crv" value')
  }

  try {
    keyPairString = await jose.generate_key_pair_jwk({ namedCurve: crv_mapped });
  } catch (error: any) {
    if(error.message === 'internal error in Neon module: Unknown curve') {
      throw new TypeError('Unknown curve')
    }

    throw error
  }
  
  const keyPair: JoseGenerateKeyPairResponse = JSON.parse(keyPairString)

  return {
    privateKey: new PrivateKeyObject(keyPair, type, options?.namedCurve),
    publicKey: new PublicKeyObject(keyPair, type, options?.namedCurve)
  }
};

export const encrypt = async (
  enc: string,
  plaintext: Uint8Array,
  cek: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array
): Promise<JoseEncryptResponse> => {
  let encryptObj

  const enc_mapped = {
    'A128CBC-HS256': ContentEncryption.A128cbcHs256,
    'A192CBC-HS384': ContentEncryption.A192cbcHs384,
    'A256CBC-HS512': ContentEncryption.A256cbcHs512,
    'A128GCM': ContentEncryption.A128gcm,
    'A192GCM': ContentEncryption.A192gcm,
    'A256GCM': ContentEncryption.A256gcm,
  }[enc]

  if(enc_mapped === undefined){
    throw new RangeError(`Unsupported enc type: "${enc}"`)
  }

  try {
    encryptObj = jose.encrypt(
      enc_mapped,
      _castToUint8Array(plaintext).buffer,
      _castToUint8Array(cek).buffer,
      _castToUint8Array(iv).buffer,
      _castToUint8Array(aad).buffer
    );
  } catch (error: any) {
    if(error.message === 'internal error in Neon module: Unknown curve') {
      throw new TypeError('Unknown curve')
    }

    throw error
  }

  return {
    ciphertext: Uint8Array.from(Buffer.from(encryptObj.ciphertext, 'base64')),
    tag: encryptObj.tag ? Uint8Array.from(Buffer.from(encryptObj.tag, 'base64')) : undefined
  }
};

export const decrypt = async (
  enc: string,
  cek: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> => {
  let decrypted

  const enc_mapped = {
    'A128CBC-HS256': ContentEncryption.A128cbcHs256,
    'A192CBC-HS384': ContentEncryption.A192cbcHs384,
    'A256CBC-HS512': ContentEncryption.A256cbcHs512,
    'A128GCM': ContentEncryption.A128gcm,
    'A192GCM': ContentEncryption.A192gcm,
    'A256GCM': ContentEncryption.A256gcm,
  }[enc]

  if(enc_mapped === undefined){
    throw new RangeError(`Unsupported enc type: "${enc}"`)
  }

  try {
    decrypted = jose.decrypt(
      enc_mapped,
      _castToUint8Array(cek).buffer,
      _castToUint8Array(ciphertext).buffer,
      _castToUint8Array(iv).buffer,
      _castToUint8Array(tag).buffer,
      _castToUint8Array(aad).buffer,
    );
  } catch (error: any) {
    if(error.message === 'internal error in Neon module: Unknown curve') {
      throw new TypeError('Unknown curve')
    }

    throw error
  }

  return Uint8Array.from(Buffer.from(decrypted, 'base64'))
}
