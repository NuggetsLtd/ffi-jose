import { ContentEncryption } from "./ContentEncryption.js";
import { KeyEncryption } from "./KeyEncryption.js";
import type { NamedCurve } from "./NamedCurve.js";
import { SigningAlgorithm } from "./SigningAlgorithm.js";

export interface JoseModule {
  readonly generate_key_pair_jwk: ({ namedCurve }: { namedCurve: NamedCurve }) => string;
  readonly generate_key_pair: () => string;
  readonly encrypt: (
    contentEncryption: ContentEncryption,
    cek: ArrayBufferLike,
    iv: ArrayBufferLike,
    plaintext: ArrayBufferLike,
    aad: ArrayBufferLike,
    didcomm: boolean
  ) => { ciphertext: string; tag?: string };
  readonly decrypt: (
    contentEncryption: ContentEncryption,
    cek: ArrayBufferLike,
    ciphertext: ArrayBufferLike,
    iv: ArrayBufferLike,
    tag: ArrayBufferLike,
    aad: ArrayBufferLike
  ) => string;
  readonly general_encrypt_json: (
    KeyEncryption: KeyEncryption,
    contentEncryption: ContentEncryption,
    payload: string,
    recipients: string,
    didcomm: boolean
  ) => string;
  readonly decrypt_json: (jwe: string, jwk: string) => string;
  readonly compact_sign_json: (alg: SigningAlgorithm, payload: string, jwk: string, didcomm: boolean) => string;
  readonly compact_json_verify: (jws: string, jwk: string) => string;
  readonly flattened_sign_json: (alg: SigningAlgorithm, payload: string, jwk: string, didcomm: boolean) => string;
  readonly json_verify: (jws: string, jwk: string) => string;
  readonly general_sign_json: (payload: string, jwk: string, didcomm: boolean) => string;
}
