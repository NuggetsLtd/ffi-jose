import type {
  JoseGenerateJwkRequest,
  JWK,
} from "./types";

/**
 * @ignore
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const jose = require(path.resolve(path.join(__dirname, "../native/index.node")));

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
