pub mod ffi;

use crate::jose::{
  NamedCurve,
  ContentEncryptionAlgorithm,
  KeyEncryptionAlgorithm,
  TokenType,
  rust_generate_key_pair_jwk,
  rust_generate_key_pair,
  rust_encrypt,
  rust_decrypt,
  rust_general_encrypt_json,
  rust_decrypt_json
};
use josekit::jwk::Jwk;
use std::os::raw::c_char;
use std::panic;
use serde::{Serialize};
use base64;

#[repr(C)]
pub struct JsonString {
  ptr: *const c_char,
}

#[no_mangle]
pub unsafe extern "C" fn ffi_jose_free_json_string(json_string: JsonString) {
  let _ = Box::from_raw(json_string.ptr as *mut c_char);
}

/// Generate JWK as JSON String
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn ffi_jose_generate_key_pair_jwk(
  named_curve: NamedCurve,
  json_string: &mut JsonString,
) -> i32 {
  let jwk = panic::catch_unwind(|| {
    // generate JWK string for specified curve
    let mut jwk_string: String = rust_generate_key_pair_jwk(named_curve);
    jwk_string.push('\0'); // add null terminator (for C-string)
    jwk_string
  });

  match jwk {
    Ok(jwk_string) => {
      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = jwk_string.into_boxed_str();
    
      // set json_string pointer to boxed jwk_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(_) => 1
  }
}

/// Generate KeyPair as JSON String
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn ffi_jose_generate_key_pair(
  named_curve: NamedCurve,
  json_string: &mut JsonString,
) -> i32 {
  let key_pair = panic::catch_unwind(|| {
    // generate key pair string for specified curve
    let mut key_pair_string: String = rust_generate_key_pair(named_curve);
    key_pair_string.push('\0'); // add null terminator (for C-string)
    key_pair_string
  });

  match key_pair {
    Ok(key_pair_string) => {
      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = key_pair_string.into_boxed_str();
    
      // set json_string pointer to boxed key_pair_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(_) => 1
  }
}

#[derive(Serialize)]
struct Encrypted {
  ciphertext: String,
  tag: Option<String>,
}

/// Encrypt message
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn ffi_jose_encrypt(
  enc: ContentEncryptionAlgorithm,
  key: ffi::ByteArray,
  iv: ffi::ByteArray,
  message: ffi::ByteArray,
  aad: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // encrypt message
  let (ciphertext, tag) = match rust_encrypt(enc, &key.to_vec(), &iv.to_vec(), &message.to_vec(), &aad.to_vec()) {
    Ok(encrypted) => encrypted,
    Err(_) => panic!("Failed to encrypt data")
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

  // Serialize `Encrypted` to a JSON string
  match serde_json::to_string(&encrypted) {
    Ok(mut encrypted_string) => {
      // add null terminator (for C-string)
      encrypted_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = encrypted_string.into_boxed_str();
    
      // set json_string pointer to boxed encrypted_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(_) => 1
  }
}

/// Decrypt message
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn ffi_jose_decrypt(
  enc: ContentEncryptionAlgorithm,
  key: ffi::ByteArray,
  ciphertext: ffi::ByteArray,
  iv: ffi::ByteArray,
  tag: ffi::ByteArray,
  aad: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // decrypt message
  let plaintext = match rust_decrypt(enc, &key.to_vec(), &ciphertext.to_vec(), &iv.to_vec(), &tag.to_vec(), &aad.to_vec()) {
    Ok(decrypted) => decrypted,
    Err(_) => panic!("Failed to decrypt data")
  };

  let mut plaintext_b64_string: String = base64::encode(plaintext);

  // add null terminator (for C-string)
  plaintext_b64_string.push('\0');

  // box the string, so string isn't de-allocated on leaving the scope of this fn
  let boxed: Box<str> = plaintext_b64_string.into_boxed_str();

  // set json_string pointer to boxed plaintext_b64_string
  json_string.ptr = Box::into_raw(boxed).cast();

  0
}

/// General Encrypt JSON
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn ffi_jose_general_encrypt_json(
  alg: KeyEncryptionAlgorithm,
  enc: ContentEncryptionAlgorithm,
  payload: ffi::ByteArray,
  recipients: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  let aad: Option<&[u8]> = None;

  // convert recipients byte array to array of Jwks
  let recipients_string = String::from_utf8(recipients.to_vec()).unwrap();
  let recipient_jwks: Vec<Jwk> = serde_json::from_str(&recipients_string).unwrap();

  // encrypt payload for recipients and return
  match rust_general_encrypt_json(
    alg,
    enc,
    TokenType::DidcommEncrypted,
    &payload.to_vec(),
    &recipient_jwks,
    aad
  ) {
    Ok(mut encrypted_string) => {
      // add null terminator (for C-string)
      encrypted_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = encrypted_string.into_boxed_str();
    
      // set json_string pointer to boxed encrypted_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(_) => 1
  }
}

/// Decrypt JSON
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn ffi_jose_decrypt_json(
  jwe: ffi::ByteArray,
  jwk: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  let jwe_string = String::from_utf8(jwe.to_vec()).unwrap();

  // convert byte array to Jwk
  let jwk_string = String::from_utf8(jwk.to_vec()).unwrap();
  let jwk: Jwk = serde_json::from_str(&jwk_string).unwrap();

  match rust_decrypt_json(&jwe_string, &jwk) {
    Ok(deserialised) => {
      let ( decrypted, _header ) = deserialised;

      let mut decrypted_string = String::from_utf8(decrypted).unwrap();
      
      // add null terminator (for C-string)
      decrypted_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = decrypted_string.into_boxed_str();
    
      // set json_string pointer to boxed encrypted_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(_) => panic!("Failed to decrypt data")
  }
}

