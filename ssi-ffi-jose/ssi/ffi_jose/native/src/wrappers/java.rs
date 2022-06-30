use jni::JNIEnv;
use jni::objects::{JClass};
use jni::sys::{jstring, jint};
use crate::jose::{ NamedCurve, rust_generate_key_pair_jwk };
use std::panic;

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
