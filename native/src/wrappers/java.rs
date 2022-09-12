use jni::JNIEnv;
use jni::objects::{JClass};
use jni::sys::{jstring, jint, jbyteArray};
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
};
use josekit::jwk::Jwk;
use std::panic;
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
      _ => panic!("Unknown curve")
    };

    // generate JWK string for specified curve
    let jwk = panic::catch_unwind(|| {
      rust_generate_key_pair_jwk(named_curve)
    });

    match jwk {
      Ok(jwk_string) => {
        let output = env
          .new_string(jwk_string)
          .expect("Unable to create string from JWK");
  
        // extract the raw pointer to return.
        output.into_inner()
      },
      Err(_) => panic!("Unable to generate keypair")
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
    _ => panic!("Unknown curve")
  };

  // generate JWK string for specified curve
  let key_pair = panic::catch_unwind(|| {
    rust_generate_key_pair(named_curve)
  });

  match key_pair {
    Ok(key_pair_string) => {
      let output = env
        .new_string(key_pair_string)
        .expect("Unable to create string from key pair");

      // extract the raw pointer to return.
      output.into_inner()
    },
    Err(_) => panic!("Unable to generate keypair")
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
    _ => panic!("Unknown `enc` value")
  };

  let key_bytes;
  let iv_bytes;
  let plaintext_bytes;
  let aad_bytes;

  match env.convert_byte_array(key) {
      Err(_) => panic!("Failed converting `key` to byte array"),
      Ok(k) => key_bytes = k,
  };
  match env.convert_byte_array(iv) {
      Err(_) => panic!("Failed converting `iv` to byte array"),
      Ok(i) => iv_bytes = i,
  };
  match env.convert_byte_array(message) {
      Err(_) => panic!("Failed converting `message` to byte array"),
      Ok(m) => plaintext_bytes = m,
  };
  match env.convert_byte_array(aad) {
      Err(_) => panic!("Failed converting `message` to byte array"),
      Ok(a) => aad_bytes = a,
  };

  let (ciphertext, tag) = match rust_encrypt(enc, &key_bytes, &iv_bytes, &plaintext_bytes, &aad_bytes) {
    Ok(encrypted) => encrypted,
    _ => panic!("Failed to encrypt data")
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
    Err(_) => panic!("Unable to generate encryped data")
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
    _ => panic!("Unknown `enc` value")
  };

  let key_bytes;
  let iv_bytes;
  let ciphertext_bytes;
  let tag_bytes;
  let aad_bytes;

  match env.convert_byte_array(key) {
      Err(_) => panic!("Failed converting `key` to byte array"),
      Ok(k) => key_bytes = k,
  };
  match env.convert_byte_array(ciphertext) {
      Err(_) => panic!("Failed converting `ciphertext` to byte array"),
      Ok(c) => ciphertext_bytes = c,
  };
  match env.convert_byte_array(iv) {
      Err(_) => panic!("Failed converting `iv` to byte array"),
      Ok(i) => iv_bytes = i,
  };
  match env.convert_byte_array(tag) {
      Err(_) => panic!("Failed converting `tag` to byte array"),
      Ok(t) => tag_bytes = t,
  };
  match env.convert_byte_array(aad) {
      Err(_) => panic!("Failed converting `message` to byte array"),
      Ok(a) => aad_bytes = a,
  };

  // decrypt ciphertext
  let decrypted = match rust_decrypt(enc, &key_bytes, &ciphertext_bytes, &iv_bytes, &tag_bytes, &aad_bytes) {
    Ok(decrypted) => decrypted,
    _ => panic!("Failed to decrypt data")
  };

  let decrypted_string = String::from_utf8(decrypted).unwrap();

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
    _ => panic!("Unknown `alg` value")
  };

  // map content encryption algorithm integers to enum options
  let enc = match enc as u8 {
    0 => ContentEncryptionAlgorithm::A128gcm,
    1 => ContentEncryptionAlgorithm::A192gcm,
    2 => ContentEncryptionAlgorithm::A256gcm,
    3 => ContentEncryptionAlgorithm::A128cbcHs256,
    4 => ContentEncryptionAlgorithm::A192cbcHs384,
    5 => ContentEncryptionAlgorithm::A256cbcHs512,
    _ => panic!("Unknown `enc` value")
  };

  let plaintext_bytes;
  match env.convert_byte_array(plaintext) {
      Err(_) => panic!("Failed converting `plaintext` to byte array"),
      Ok(p) => plaintext_bytes = p,
  };

  let recipients_bytes;
  match env.convert_byte_array(recipients) {
      Err(_) => panic!("Failed converting `recipients` to byte array"),
      Ok(r) => recipients_bytes = r,
  };

  // convert recipients byte array to array of Jwks
  let recipients_string = String::from_utf8(recipients_bytes.to_vec()).unwrap();
  let recipient_jwks: Vec<Jwk> = serde_json::from_str(&recipients_string).unwrap();

  // encrypt JSON to JWE
  let encrypted = match rust_general_encrypt_json(
    alg,
    enc,
    TokenType::DidcommEncrypted,
    &plaintext_bytes.to_vec(),
    &recipient_jwks,
    aad
  ) {
    Ok(encrypted) => encrypted,
    _ => panic!("Failed to decrypt data")
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
  let jwe_bytes;
  match env.convert_byte_array(jwe) {
      Err(_) => panic!("Failed converting `jwe` to byte array"),
      Ok(j) => jwe_bytes = j,
  };

  let jwk_bytes;
  match env.convert_byte_array(jwk) {
      Err(_) => panic!("Failed converting `jwk` to byte array"),
      Ok(k) => jwk_bytes = k,
  };

  let jwe_string = String::from_utf8(jwe_bytes.to_vec()).unwrap();

  // convert jwk byte array to Jwk
  let jwk_string = String::from_utf8(jwk_bytes.to_vec()).unwrap();
  let jwk: Jwk = serde_json::from_str(&jwk_string).unwrap();

  // decrypt JWE to JSON
  let (decrypted, _header) = match rust_decrypt_json(
    &jwe_string,
    &jwk,
  ) {
    Ok(decrypted) => decrypted,
    _ => panic!("Failed to decrypt data")
  };

  let decrypted_string = String::from_utf8(decrypted).unwrap();

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
    _ => panic!("Unknown `alg` value")
  };

  let payload_bytes;
  match env.convert_byte_array(payload) {
      Err(_) => panic!("Failed converting `payload` to byte array"),
      Ok(p) => payload_bytes = p,
  };

  let jwk_bytes;
  match env.convert_byte_array(jwk) {
      Err(_) => panic!("Failed converting `jwk` to byte array"),
      Ok(r) => jwk_bytes = r,
  };

  // convert jwk byte array to array of Jwks
  let jwk_string = String::from_utf8(jwk_bytes.to_vec()).unwrap();
  let signer_jwk: Jwk = serde_json::from_str(&jwk_string).unwrap();

  // sign JSON to JWS
  let signed = match rust_compact_sign_json(
    alg,
    TokenType::DidcommSigned,
    &payload_bytes.to_vec(),
    &signer_jwk
  ) {
    Ok(signed) => signed,
    _ => panic!("Failed to sign data")
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
  let jws_bytes;
  match env.convert_byte_array(jws) {
      Err(_) => panic!("Failed converting `jws` to byte array"),
      Ok(j) => jws_bytes = j,
  };

  let jwk_bytes;
  match env.convert_byte_array(jwk) {
      Err(_) => panic!("Failed converting `jwk` to byte array"),
      Ok(k) => jwk_bytes = k,
  };

  let jws_string = String::from_utf8(jws_bytes.to_vec()).unwrap();

  // convert jwk byte array to Jwk
  let jwk_string = String::from_utf8(jwk_bytes.to_vec()).unwrap();
  let jwk: Jwk = serde_json::from_str(&jwk_string).unwrap();

  // decrypt JWs to JSON
  let (payload, _header) = match rust_compact_json_verify(
    &jws_string,
    &jwk,
  ) {
    Ok(payload) => payload,
    _ => panic!("Failed to verify data")
  };

  let payload_string = String::from_utf8(payload).unwrap();

  let output = env
        .new_string(payload_string)
        .expect("Unable to create string from payload data");

  output.into_inner()
}

