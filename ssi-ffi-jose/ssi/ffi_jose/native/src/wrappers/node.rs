#[macro_use]
mod macros;

use neon::prelude::*;
use base64;
use crate::jose::{
  NamedCurve,
  rust_generate_key_pair_jwk,
  ContentEncryptionAlgorithm,
  rust_encrypt,
  rust_decrypt
};

fn node_generate_key_pair_jwk(mut cx: FunctionContext) -> JsResult<JsString> {
  let options = cx.argument::<JsObject>(0)?;

  let named_curve_num: Handle<JsNumber> = options.get::<JsNumber, _, _>(&mut cx, "namedCurve")?;

  let named_curve = match named_curve_num.value() as u8 {
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

  let jwk_string: String = rust_generate_key_pair_jwk(named_curve);

  Ok(JsString::new(&mut cx, jwk_string))
}

fn node_encrypt(mut cx: FunctionContext) -> JsResult<JsObject> {
  let enc = cx.argument::<JsNumber>(0)?;
  let message = arg_to_slice!(cx, 1);
  let key = arg_to_slice!(cx, 2);
  let iv = arg_to_slice!(cx, 3);
  let aad = arg_to_slice!(cx, 4);

  // determine content encryption type
  let content_encryption = match enc.value() as u8 {
    0 => ContentEncryptionAlgorithm::A128gcm,
    1 => ContentEncryptionAlgorithm::A192gcm,
    2 => ContentEncryptionAlgorithm::A256gcm,
    3 => ContentEncryptionAlgorithm::A128cbcHs256,
    4 => ContentEncryptionAlgorithm::A192cbcHs384,
    5 => ContentEncryptionAlgorithm::A256cbcHs512,
    _ => panic!("Unsupported content encryption method")
  };

  // encrypt message
  let (ciphertext, tag) = match rust_encrypt(content_encryption, &key, &iv, &message, &aad) {
    Ok(encrypted) => encrypted,
    Err(_) => panic!("Failed to encrypt data")
  };

  let result = JsObject::new(&mut cx);
  
  // add base64 encoded ciphertext to return object
  let ciphertext_b64: String = base64::encode(ciphertext);
  let ciphertext_b64 = JsString::new(&mut cx, ciphertext_b64);
  result.set(&mut cx, "ciphertext", ciphertext_b64)?;

  match tag {
    Some(tag) => {
      // add optional tag to return object
      let tag_b64: String = base64::encode(tag);
      let tag_b64 = JsString::new(&mut cx, tag_b64);
      result.set(&mut cx, "tag", tag_b64)?;
    },
    None => ()
  }
  
  Ok(result)
}

fn node_decrypt(mut cx: FunctionContext) -> JsResult<JsString> {
  let enc = cx.argument::<JsNumber>(0)?;
  let key = arg_to_slice!(cx, 1);
  let ciphertext = arg_to_slice!(cx, 2);
  let iv = arg_to_slice!(cx, 3);
  let tag = arg_to_slice!(cx, 4);
  let aad = arg_to_slice!(cx, 5);

  // determine content encryption type
  let content_encryption = match enc.value() as u8 {
    0 => ContentEncryptionAlgorithm::A128gcm,
    1 => ContentEncryptionAlgorithm::A192gcm,
    2 => ContentEncryptionAlgorithm::A256gcm,
    3 => ContentEncryptionAlgorithm::A128cbcHs256,
    4 => ContentEncryptionAlgorithm::A192cbcHs384,
    5 => ContentEncryptionAlgorithm::A256cbcHs512,
    _ => panic!("Unsupported content encryption method")
  };

  // decrypt message
  let plaintext = match rust_decrypt(content_encryption, &key, &ciphertext, &iv, &tag, &aad) {
    Ok(decrypted) => decrypted,
    Err(_) => panic!("Failed to decrypt data")
  };

  let plaintext_b64: String = base64::encode(plaintext);

  Ok(JsString::new(&mut cx, plaintext_b64))
}

register_module!(mut cx, {
  cx.export_function("generate_key_pair_jwk", node_generate_key_pair_jwk)?;
  cx.export_function("encrypt", node_encrypt)?;
  cx.export_function("decrypt", node_decrypt)?;
  Ok(())
});
