use crate::jose::{ rust_generate_key_pair_jwk };
use std::os::raw::c_char;
use std::panic;

pub use crate::jose::NamedCurve;

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
pub unsafe extern "C" fn generate_key_pair_jwk(
  named_curve: NamedCurve,
  json_string: &mut JwkJsonString,
  // err: &mut ExternError,
) -> i32 {
  let result = panic::catch_unwind(|| {
    // generate JWK string for specified curve
    let mut jwk_string: String = rust_generate_key_pair_jwk(named_curve);
    jwk_string.push('\0'); // add null terminator (for C-string)
    jwk_string
  });

  match result {
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
pub unsafe extern "C" fn free_jwk_string(jwk_string: JwkJsonString) {
  let _ = Box::from_raw(jwk_string.ptr as *mut c_char);
}
