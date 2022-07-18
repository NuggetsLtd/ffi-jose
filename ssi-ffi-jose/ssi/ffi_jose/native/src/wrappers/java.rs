use jni::JNIEnv;
use jni::objects::{JClass};
use jni::sys::{jstring, jint, jbyteArray};
use crate::jose::{
  NamedCurve,
  ContentEncryptionAlgorithm,
  rust_generate_key_pair_jwk,
  rust_generate_key_pair,
  rust_encrypt
};
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

  let public_key;
  let initialisation_vector;
  let plaintext;
  let additional_data;

  match env.convert_byte_array(key) {
      Err(_) => panic!("Failed converting `key` to byte array"),
      Ok(k) => public_key = k,
  };
  match env.convert_byte_array(iv) {
      Err(_) => panic!("Failed converting `iv` to byte array"),
      Ok(i) => initialisation_vector = i,
  };
  match env.convert_byte_array(message) {
      Err(_) => panic!("Failed converting `message` to byte array"),
      Ok(m) => plaintext = m,
  };
  match env.convert_byte_array(aad) {
      Err(_) => panic!("Failed converting `message` to byte array"),
      Ok(a) => additional_data = a,
  };

  let (ciphertext, tag) = match rust_encrypt(enc, &public_key, &initialisation_vector, &plaintext, &additional_data) {
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
