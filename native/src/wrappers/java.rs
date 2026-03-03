#[macro_use]
mod macros;

use jni::JNIEnv;
use jni::objects::{JClass};
use jni::sys::{jstring, jint, jbyteArray, jboolean, JNI_FALSE};
use crate::jose::{
  NamedCurve,
  ContentEncryptionAlgorithm,
  KeyEncryptionAlgorithm,
  SigningAlgorithm,
  TokenType,
  rust_generate_key_pair_jwk,
  rust_generate_key_pair,
  rust_encrypt,
  rust_decrypt,
  rust_general_encrypt_json,
  rust_decrypt_json,
  rust_compact_sign_json,
  rust_compact_json_verify,
  rust_flattened_sign_json,
  rust_json_verify,
  rust_general_sign_json,
};
use josekit::jwk::Jwk;
use std::panic::{self, AssertUnwindSafe};
use serde::{Serialize};
use base64;

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_generate_1key_1pair_1jwk(
  env: JNIEnv,
  _class: JClass,
  named_curve: jint
) -> jstring {
    // map named curve integers to enum options
    let named_curve = match named_curve as u8 {
      0 => NamedCurve::P256,
      1 => NamedCurve::P384,
      2 => NamedCurve::P521,
      3 => NamedCurve::Secp256k1,
      4 => NamedCurve::Ed25519,
      5 => NamedCurve::Ed448,
      6 => NamedCurve::X25519,
      7 => NamedCurve::X448,
      _ => { handle_err!("Unknown curve", env); }
    };

    // generate JWK string for specified curve
    let jwk = panic::catch_unwind(AssertUnwindSafe(|| {
      rust_generate_key_pair_jwk(named_curve)
    }));

    match jwk {
      Ok(jwk_string) => {
        let output = env
          .new_string(jwk_string)
          .expect("Unable to create string from JWK");

        // extract the raw pointer to return.
        output.into_inner()
      },
      Err(_) => { handle_err!("Unable to generate keypair", env); }
    }
}

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_generate_1key_1pair(
  env: JNIEnv,
  _class: JClass,
  named_curve: jint
) -> jstring {
  // map named curve integers to enum options
  let named_curve = match named_curve as u8 {
    0 => NamedCurve::P256,
    1 => NamedCurve::P384,
    2 => NamedCurve::P521,
    3 => NamedCurve::Secp256k1,
    4 => NamedCurve::Ed25519,
    5 => NamedCurve::Ed448,
    6 => NamedCurve::X25519,
    7 => NamedCurve::X448,
    _ => { handle_err!("Unknown curve", env); }
  };

  // generate JWK string for specified curve
  let key_pair = panic::catch_unwind(AssertUnwindSafe(|| {
    rust_generate_key_pair(named_curve)
  }));

  match key_pair {
    Ok(key_pair_string) => {
      let output = env
        .new_string(key_pair_string)
        .expect("Unable to create string from key pair");

      // extract the raw pointer to return.
      output.into_inner()
    },
    Err(_) => { handle_err!("Unable to generate keypair", env); }
  }
}

#[derive(Serialize,Debug)]
struct Encrypted {
  ciphertext: String,
  tag: Option<String>,
}

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_encrypt(
  env: JNIEnv,
  _class: JClass,
  enc: jint,
  key: jbyteArray,
  iv: jbyteArray,
  message: jbyteArray,
  aad: jbyteArray,
) -> jstring {
  // map content encryption algorithm integers to enum options
  let enc = match enc as u8 {
    0 => ContentEncryptionAlgorithm::A128gcm,
    1 => ContentEncryptionAlgorithm::A192gcm,
    2 => ContentEncryptionAlgorithm::A256gcm,
    3 => ContentEncryptionAlgorithm::A128cbcHs256,
    4 => ContentEncryptionAlgorithm::A192cbcHs384,
    5 => ContentEncryptionAlgorithm::A256cbcHs512,
    _ => { handle_err!("Unknown `enc` value", env); }
  };

  let key_bytes = match env.convert_byte_array(key) {
      Err(_) => { handle_err!("Failed converting `key` to byte array", env); }
      Ok(k) => k,
  };
  let iv_bytes = match env.convert_byte_array(iv) {
      Err(_) => { handle_err!("Failed converting `iv` to byte array", env); }
      Ok(i) => i,
  };
  let plaintext_bytes = match env.convert_byte_array(message) {
      Err(_) => { handle_err!("Failed converting `message` to byte array", env); }
      Ok(m) => m,
  };
  let aad_bytes = match env.convert_byte_array(aad) {
      Err(_) => { handle_err!("Failed converting `aad` to byte array", env); }
      Ok(a) => a,
  };

  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    rust_encrypt(enc, &key_bytes, &iv_bytes, &plaintext_bytes, &aad_bytes)
  }));

  let (ciphertext, tag) = match result {
    Ok(Ok(encrypted)) => encrypted,
    Ok(Err(e)) => { handle_err!(format!("Failed to encrypt data: {}", e), env); }
    Err(_) => { handle_err!("Failed to encrypt data: internal error", env); }
  };

  // populate `Encrypted` instance
  let encrypted = match tag {
    Some(tag) => {
      Encrypted {
        ciphertext: base64::encode(ciphertext),
        tag: Some(base64::encode(tag)),
      }
    },
    None => {
      Encrypted {
        ciphertext: base64::encode(ciphertext),
        tag: None,
      }
    }
  };

  // serialise & return
  match serde_json::to_string(&encrypted) {
    Ok(encrypted_bytes) => {
      let output = env
        .new_string(encrypted_bytes)
        .expect("Unable to create string from encrypted data");

      // extract the raw pointer to return.
      output.into_inner()
    },
    Err(_) => { handle_err!("Unable to serialize encrypted data", env); }
  }
}

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_decrypt(
  env: JNIEnv,
  _class: JClass,
  enc: jint,
  key: jbyteArray,
  ciphertext: jbyteArray,
  iv: jbyteArray,
  tag: jbyteArray,
  aad: jbyteArray,
) -> jstring {
  // map content encryption algorithm integers to enum options
  let enc = match enc as u8 {
    0 => ContentEncryptionAlgorithm::A128gcm,
    1 => ContentEncryptionAlgorithm::A192gcm,
    2 => ContentEncryptionAlgorithm::A256gcm,
    3 => ContentEncryptionAlgorithm::A128cbcHs256,
    4 => ContentEncryptionAlgorithm::A192cbcHs384,
    5 => ContentEncryptionAlgorithm::A256cbcHs512,
    _ => { handle_err!("Unknown `enc` value", env); }
  };

  let key_bytes = match env.convert_byte_array(key) {
      Err(_) => { handle_err!("Failed converting `key` to byte array", env); }
      Ok(k) => k,
  };
  let ciphertext_bytes = match env.convert_byte_array(ciphertext) {
      Err(_) => { handle_err!("Failed converting `ciphertext` to byte array", env); }
      Ok(c) => c,
  };
  let iv_bytes = match env.convert_byte_array(iv) {
      Err(_) => { handle_err!("Failed converting `iv` to byte array", env); }
      Ok(i) => i,
  };
  let tag_bytes = match env.convert_byte_array(tag) {
      Err(_) => { handle_err!("Failed converting `tag` to byte array", env); }
      Ok(t) => t,
  };
  let aad_bytes = match env.convert_byte_array(aad) {
      Err(_) => { handle_err!("Failed converting `aad` to byte array", env); }
      Ok(a) => a,
  };

  // decrypt ciphertext
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    rust_decrypt(enc, &key_bytes, &ciphertext_bytes, &iv_bytes, &tag_bytes, &aad_bytes)
  }));

  let decrypted = match result {
    Ok(Ok(decrypted)) => decrypted,
    Ok(Err(e)) => { handle_err!(format!("Failed to decrypt data: {}", e), env); }
    Err(_) => { handle_err!("Failed to decrypt data: internal error", env); }
  };

  let decrypted_string = match String::from_utf8(decrypted) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode decrypted data as UTF-8", env); }
  };

  let output = env
        .new_string(decrypted_string)
        .expect("Unable to create string from decrypted data");

  output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_general_1encrypt_1json(
  env: JNIEnv,
  _class: JClass,
  alg: jint,
  enc: jint,
  plaintext: jbyteArray,
  recipients: jbyteArray,
  didcomm: jboolean,
) -> jstring {
  let aad: Option<&[u8]> = None;

  // map key encryption algorithm integers to enum options
  let alg = match alg as u8 {
    0 => KeyEncryptionAlgorithm::Dir,
    1 => KeyEncryptionAlgorithm::EcdhEs,
    2 => KeyEncryptionAlgorithm::EcdhEsA128kw,
    3 => KeyEncryptionAlgorithm::EcdhEsA192kw,
    4 => KeyEncryptionAlgorithm::EcdhEsA256kw,
    5 => KeyEncryptionAlgorithm::Rsa1_5,
    6 => KeyEncryptionAlgorithm::RsaOaep,
    7 => KeyEncryptionAlgorithm::RsaOaep256,
    8 => KeyEncryptionAlgorithm::RsaOaep384,
    9 => KeyEncryptionAlgorithm::RsaOaep512,
    10 => KeyEncryptionAlgorithm::Pbes2Hs256A128kw,
    11 => KeyEncryptionAlgorithm::Pbes2Hs384A192kw,
    12 => KeyEncryptionAlgorithm::Pbes2Hs512A256kw,
    13 => KeyEncryptionAlgorithm::A128kw,
    14 => KeyEncryptionAlgorithm::A192kw,
    15 => KeyEncryptionAlgorithm::A256kw,
    16 => KeyEncryptionAlgorithm::A128gcmkw,
    17 => KeyEncryptionAlgorithm::A192gcmkw,
    18 => KeyEncryptionAlgorithm::A256gcmkw,
    _ => { handle_err!("Unknown `alg` value", env); }
  };

  // map content encryption algorithm integers to enum options
  let enc = match enc as u8 {
    0 => ContentEncryptionAlgorithm::A128gcm,
    1 => ContentEncryptionAlgorithm::A192gcm,
    2 => ContentEncryptionAlgorithm::A256gcm,
    3 => ContentEncryptionAlgorithm::A128cbcHs256,
    4 => ContentEncryptionAlgorithm::A192cbcHs384,
    5 => ContentEncryptionAlgorithm::A256cbcHs512,
    _ => { handle_err!("Unknown `enc` value", env); }
  };

  let plaintext_bytes = match env.convert_byte_array(plaintext) {
      Err(_) => { handle_err!("Failed converting `plaintext` to byte array", env); }
      Ok(p) => p,
  };

  let recipients_bytes = match env.convert_byte_array(recipients) {
      Err(_) => { handle_err!("Failed converting `recipients` to byte array", env); }
      Ok(r) => r,
  };

  // convert recipients byte array to array of Jwks
  let recipients_string = match String::from_utf8(recipients_bytes.to_vec()) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode recipients as UTF-8", env); }
  };
  let recipient_jwks: Vec<Jwk> = match serde_json::from_str(&recipients_string) {
    Ok(jwks) => jwks,
    Err(e) => { handle_err!(format!("Failed to parse recipients JSON: {}", e), env); }
  };

  let typ = if didcomm != JNI_FALSE { TokenType::DidcommEncrypted } else { TokenType::JWT };

  // encrypt JSON to JWE
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    rust_general_encrypt_json(
      alg,
      enc,
      typ,
      &plaintext_bytes.to_vec(),
      &recipient_jwks,
      aad
    )
  }));

  let encrypted = match result {
    Ok(Ok(encrypted)) => encrypted,
    Ok(Err(e)) => { handle_err!(format!("Failed to encrypt data: {}", e), env); }
    Err(_) => { handle_err!("Failed to encrypt data: internal error", env); }
  };

  let output = env
        .new_string(encrypted)
        .expect("Unable to create string from encrypted data");

  output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_decrypt_1json(
  env: JNIEnv,
  _class: JClass,
  jwe: jbyteArray,
  jwk: jbyteArray,
) -> jstring {
  let jwe_bytes = match env.convert_byte_array(jwe) {
      Err(_) => { handle_err!("Failed converting `jwe` to byte array", env); }
      Ok(j) => j,
  };

  let jwk_bytes = match env.convert_byte_array(jwk) {
      Err(_) => { handle_err!("Failed converting `jwk` to byte array", env); }
      Ok(k) => k,
  };

  let jwe_string = match String::from_utf8(jwe_bytes.to_vec()) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode JWE as UTF-8", env); }
  };

  // convert jwk byte array to Jwk
  let jwk_string = match String::from_utf8(jwk_bytes.to_vec()) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode JWK as UTF-8", env); }
  };
  let jwk: Jwk = match serde_json::from_str(&jwk_string) {
    Ok(k) => k,
    Err(e) => { handle_err!(format!("Failed to parse JWK JSON: {}", e), env); }
  };

  // decrypt JWE to JSON
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    rust_decrypt_json(
      &jwe_string,
      &jwk,
    )
  }));

  let (decrypted, _header) = match result {
    Ok(Ok(decrypted)) => decrypted,
    Ok(Err(e)) => { handle_err!(format!("Failed to decrypt data: {}", e), env); }
    Err(_) => { handle_err!("Failed to decrypt data: internal error", env); }
  };

  let decrypted_string = match String::from_utf8(decrypted) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode decrypted data as UTF-8", env); }
  };

  let output = env
        .new_string(decrypted_string)
        .expect("Unable to create string from decrypted data");

  output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_compact_1sign_1json(
  env: JNIEnv,
  _class: JClass,
  alg: jint,
  payload: jbyteArray,
  jwk: jbyteArray,
  didcomm: jboolean,
) -> jstring {
  // map signing algorithm integers to enum options
  let alg = match alg as u8 {
    // ECDSA
    0 => SigningAlgorithm::Es256,
    1 => SigningAlgorithm::Es384,
    2 => SigningAlgorithm::Es512,
    3 => SigningAlgorithm::Es256k,
    // EdDSA
    4 => SigningAlgorithm::Eddsa,
    // HMAC
    5 => SigningAlgorithm::Hs256,
    6 => SigningAlgorithm::Hs384,
    7 => SigningAlgorithm::Hs512,
    // RSA
    8 => SigningAlgorithm::Rs256,
    9 => SigningAlgorithm::Rs384,
    10 => SigningAlgorithm::Rs512,
    // RSA PSS
    11 => SigningAlgorithm::Ps256,
    12 => SigningAlgorithm::Ps384,
    13 => SigningAlgorithm::Ps512,
    _ => { handle_err!("Unknown `alg` value", env); }
  };

  let payload_bytes = match env.convert_byte_array(payload) {
      Err(_) => { handle_err!("Failed converting `payload` to byte array", env); }
      Ok(p) => p,
  };

  let jwk_bytes = match env.convert_byte_array(jwk) {
      Err(_) => { handle_err!("Failed converting `jwk` to byte array", env); }
      Ok(r) => r,
  };

  // convert jwk byte array to Jwk
  let jwk_string = match String::from_utf8(jwk_bytes.to_vec()) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode JWK as UTF-8", env); }
  };
  let signer_jwk: Jwk = match serde_json::from_str(&jwk_string) {
    Ok(k) => k,
    Err(e) => { handle_err!(format!("Failed to parse JWK JSON: {}", e), env); }
  };

  let typ = if didcomm != JNI_FALSE { TokenType::DidcommSigned } else { TokenType::JWT };

  // sign JSON to JWS
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    rust_compact_sign_json(
      alg,
      typ,
      &payload_bytes.to_vec(),
      &signer_jwk
    )
  }));

  let signed = match result {
    Ok(Ok(signed)) => signed,
    Ok(Err(e)) => { handle_err!(format!("Failed to sign data: {}", e), env); }
    Err(_) => { handle_err!("Failed to sign data: internal error", env); }
  };

  let output = env
        .new_string(signed)
        .expect("Unable to create string from signed data");

  output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_compact_1json_1verify(
  env: JNIEnv,
  _class: JClass,
  jws: jbyteArray,
  jwk: jbyteArray,
) -> jstring {
  let jws_bytes = match env.convert_byte_array(jws) {
      Err(_) => { handle_err!("Failed converting `jws` to byte array", env); }
      Ok(j) => j,
  };

  let jwk_bytes = match env.convert_byte_array(jwk) {
      Err(_) => { handle_err!("Failed converting `jwk` to byte array", env); }
      Ok(k) => k,
  };

  let jws_string = match String::from_utf8(jws_bytes.to_vec()) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode JWS as UTF-8", env); }
  };

  // convert jwk byte array to Jwk
  let jwk_string = match String::from_utf8(jwk_bytes.to_vec()) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode JWK as UTF-8", env); }
  };
  let jwk: Jwk = match serde_json::from_str(&jwk_string) {
    Ok(k) => k,
    Err(e) => { handle_err!(format!("Failed to parse JWK JSON: {}", e), env); }
  };

  // verify JWS
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    rust_compact_json_verify(
      &jws_string,
      &jwk,
    )
  }));

  let (payload, _header) = match result {
    Ok(Ok(payload)) => payload,
    Ok(Err(e)) => { handle_err!(format!("Failed to verify data: {}", e), env); }
    Err(_) => { handle_err!("Failed to verify data: internal error", env); }
  };

  let payload_string = match String::from_utf8(payload) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode verified payload as UTF-8", env); }
  };

  let output = env
        .new_string(payload_string)
        .expect("Unable to create string from payload data");

  output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_flattened_1sign_1json(
  env: JNIEnv,
  _class: JClass,
  alg: jint,
  payload: jbyteArray,
  jwk: jbyteArray,
  didcomm: jboolean,
) -> jstring {
  // map signing algorithm integers to enum options
  let alg = match alg as u8 {
    // ECDSA
    0 => SigningAlgorithm::Es256,
    1 => SigningAlgorithm::Es384,
    2 => SigningAlgorithm::Es512,
    3 => SigningAlgorithm::Es256k,
    // EdDSA
    4 => SigningAlgorithm::Eddsa,
    // HMAC
    5 => SigningAlgorithm::Hs256,
    6 => SigningAlgorithm::Hs384,
    7 => SigningAlgorithm::Hs512,
    // RSA
    8 => SigningAlgorithm::Rs256,
    9 => SigningAlgorithm::Rs384,
    10 => SigningAlgorithm::Rs512,
    // RSA PSS
    11 => SigningAlgorithm::Ps256,
    12 => SigningAlgorithm::Ps384,
    13 => SigningAlgorithm::Ps512,
    _ => { handle_err!("Unknown `alg` value", env); }
  };

  let payload_bytes = match env.convert_byte_array(payload) {
      Err(_) => { handle_err!("Failed converting `payload` to byte array", env); }
      Ok(p) => p,
  };

  let jwk_bytes = match env.convert_byte_array(jwk) {
      Err(_) => { handle_err!("Failed converting `jwk` to byte array", env); }
      Ok(r) => r,
  };

  // convert jwk byte array to Jwk
  let jwk_string = match String::from_utf8(jwk_bytes.to_vec()) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode JWK as UTF-8", env); }
  };
  let signer_jwk: Jwk = match serde_json::from_str(&jwk_string) {
    Ok(k) => k,
    Err(e) => { handle_err!(format!("Failed to parse JWK JSON: {}", e), env); }
  };

  let typ = if didcomm != JNI_FALSE { TokenType::DidcommSigned } else { TokenType::JWT };

  // sign JSON to JWS (flattened)
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    rust_flattened_sign_json(
      alg,
      typ,
      &payload_bytes.to_vec(),
      &signer_jwk
    )
  }));

  let signed = match result {
    Ok(Ok(signed)) => signed,
    Ok(Err(e)) => { handle_err!(format!("Failed to sign data: {}", e), env); }
    Err(_) => { handle_err!("Failed to sign data: internal error", env); }
  };

  let output = env
        .new_string(signed)
        .expect("Unable to create string from signed data");

  output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_json_1verify(
  env: JNIEnv,
  _class: JClass,
  jws: jbyteArray,
  jwk: jbyteArray,
) -> jstring {
  let jws_bytes = match env.convert_byte_array(jws) {
      Err(_) => { handle_err!("Failed converting `jws` to byte array", env); }
      Ok(j) => j,
  };

  let jwk_bytes = match env.convert_byte_array(jwk) {
      Err(_) => { handle_err!("Failed converting `jwk` to byte array", env); }
      Ok(k) => k,
  };

  let jws_string = match String::from_utf8(jws_bytes.to_vec()) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode JWS as UTF-8", env); }
  };

  // convert jwk byte array to Jwk
  let jwk_string = match String::from_utf8(jwk_bytes.to_vec()) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode JWK as UTF-8", env); }
  };
  let jwk: Jwk = match serde_json::from_str(&jwk_string) {
    Ok(k) => k,
    Err(e) => { handle_err!(format!("Failed to parse JWK JSON: {}", e), env); }
  };

  // verify JWS
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    rust_json_verify(
      &jws_string,
      &jwk,
    )
  }));

  let (payload, _header) = match result {
    Ok(Ok(payload)) => payload,
    Ok(Err(e)) => { handle_err!(format!("Failed to verify data: {}", e), env); }
    Err(_) => { handle_err!("Failed to verify data: internal error", env); }
  };

  let payload_string = match String::from_utf8(payload) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode verified payload as UTF-8", env); }
  };

  let output = env
        .new_string(payload_string)
        .expect("Unable to create string from payload data");

  output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Jose_general_1sign_1json(
  env: JNIEnv,
  _class: JClass,
  payload: jbyteArray,
  jwks: jbyteArray,
  didcomm: jboolean,
) -> jstring {
  let payload_bytes = match env.convert_byte_array(payload) {
      Err(_) => { handle_err!("Failed converting `payload` to byte array", env); }
      Ok(p) => p,
  };

  let jwks_bytes = match env.convert_byte_array(jwks) {
      Err(_) => { handle_err!("Failed converting `jwks` to byte array", env); }
      Ok(r) => r,
  };

  // convert jwk byte array to array of Jwks
  let jwks_string = match String::from_utf8(jwks_bytes.to_vec()) {
    Ok(s) => s,
    Err(_) => { handle_err!("Failed to decode JWKs as UTF-8", env); }
  };
  let signer_jwks: Vec<Jwk> = match serde_json::from_str(&jwks_string) {
    Ok(jwks) => jwks,
    Err(e) => { handle_err!(format!("Failed to parse JWKs JSON: {}", e), env); }
  };

  let typ = if didcomm != JNI_FALSE { TokenType::DidcommSigned } else { TokenType::JWT };

  // sign JSON to JWS (general)
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    rust_general_sign_json(
      typ,
      &payload_bytes.to_vec(),
      &signer_jwks
    )
  }));

  let signed = match result {
    Ok(Ok(signed)) => signed,
    Ok(Err(e)) => { handle_err!(format!("Failed to sign data: {}", e), env); }
    Err(_) => { handle_err!("Failed to sign data: internal error", env); }
  };

  let output = env
      .new_string(signed)
      .expect("Unable to create string from signed data");

  output.into_inner()
}
