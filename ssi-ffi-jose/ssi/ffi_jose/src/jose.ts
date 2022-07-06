import {
  JoseGenerateJwkRequest,
  JWK,
  JoseEncryptResponse,
  ContentEncryption,
} from "./types";

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
  const { namedCurve } = request;
  let jwkString

  try {
    jwkString = jose.generate_key_pair_jwk({ namedCurve });
  } catch (error: any) {
    if(error.message === 'internal error in Neon module: Unknown curve') {
      throw new TypeError('Unknown curve')
    }

    throw error
  }
  
  return JSON.parse(jwkString)
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
