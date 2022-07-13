pub mod ffi;

use crate::jose::{
  NamedCurve,
  ContentEncryptionAlgorithm,
  rust_generate_key_pair_jwk,
  rust_generate_key_pair,
  rust_encrypt,
  rust_decrypt
};
use std::os::raw::c_char;
use std::panic;
use serde::{Serialize};
use base64;

#[repr(C)]
pub struct JwkJsonString {
  ptr: *const c_char,
}

/// Generate JWK as JSON String
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn ffi_jose_generate_key_pair_jwk(
  named_curve: NamedCurve,
  json_string: &mut JwkJsonString,
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

#[no_mangle]
pub unsafe extern "C" fn ffi_jose_free_jwk_string(jwk_string: JwkJsonString) {
  let _ = Box::from_raw(jwk_string.ptr as *mut c_char);
}

#[repr(C)]
pub struct KeyPairJsonString {
  ptr: *const c_char,
}

/// Generate KeyPair as JSON String
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn ffi_jose_generate_key_pair(
  named_curve: NamedCurve,
  json_string: &mut KeyPairJsonString,
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

#[no_mangle]
pub unsafe extern "C" fn ffi_jose_free_key_pair_string(key_pair_string: KeyPairJsonString) {
  let _ = Box::from_raw(key_pair_string.ptr as *mut c_char);
}

#[repr(C)]
pub struct EncryptedJsonString {
  ptr: *const c_char,
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
  json_string: &mut EncryptedJsonString,
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

#[no_mangle]
pub unsafe extern "C" fn ffi_jose_free_encrypted_string(encrypted_string: EncryptedJsonString) {
  let _ = Box::from_raw(encrypted_string.ptr as *mut c_char);
}

#[repr(C)]
pub struct DecryptedString {
  ptr: *const c_char,
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
  decrypted_string: &mut DecryptedString,
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
  decrypted_string.ptr = Box::into_raw(boxed).cast();

  0
}

#[no_mangle]
pub unsafe extern "C" fn ffi_jose_free_decrypted_string(decrypted_string: DecryptedString) {
  let _ = Box::from_raw(decrypted_string.ptr as *mut c_char);
}
