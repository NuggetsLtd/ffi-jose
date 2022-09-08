#[macro_use]
mod macros;

use neon::prelude::*;
use base64;
use serde_json;
use crate::jose::{
  ContentEncryptionAlgorithm,
  KeyEncryptionAlgorithm,
  NamedCurve,
  TokenType,
  SigningAlgorithm,
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

fn node_generate_key_pair(mut cx: FunctionContext) -> JsResult<JsString> {
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

  let json_string: String = rust_generate_key_pair(named_curve);

  Ok(JsString::new(&mut cx, json_string))
}

fn node_encrypt(mut cx: FunctionContext) -> JsResult<JsObject> {
  let enc = cx.argument::<JsNumber>(0)?;
  let key = arg_to_slice!(cx, 1);
  let iv = arg_to_slice!(cx, 2);
  let message = arg_to_slice!(cx, 3);
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

fn node_general_encrypt_json(mut cx: FunctionContext) -> JsResult<JsString> {
  let alg = cx.argument::<JsNumber>(0)?;
  let enc = cx.argument::<JsNumber>(1)?;
  let payload = cx.argument::<JsString>(2)?;
  let recipients = cx.argument::<JsString>(3)?;
  let aad: Option<&[u8]> = None;

  // determine key encryption type
  let key_encryption = match alg.value() as u8 {
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
    _ => panic!("Unsupported key encryption method")
  };

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

  // convert serialised data to array of Jwks
  let recipient_jwks: Vec<Jwk> = serde_json::from_str(&recipients.value()).unwrap();

  // convert JsString to String
  let payload_string: String = payload.value();

  // decrypt message
  let encrypted = match rust_general_encrypt_json(
    key_encryption,
    content_encryption,
    TokenType::DidcommEncrypted,
    payload_string.as_bytes(),
    &recipient_jwks,
    aad
  ) {
    Ok(encrypted) => encrypted,
    Err(_) => panic!("Failed to encrypt data")
  };

  Ok(JsString::new(&mut cx, encrypted))
}

fn node_decrypt_json(mut cx: FunctionContext) -> JsResult<JsString> {
  let jwe = cx.argument::<JsString>(0)?;
  let jwk_string = cx.argument::<JsString>(1)?;

  let jwk: Jwk = serde_json::from_str(&jwk_string.value()).unwrap();
  
  match rust_decrypt_json(&jwe.value(), &jwk) {
    Ok(deserialised) => {
      let ( decrypted, _header ) = deserialised;
      let decrypted_string = String::from_utf8(decrypted).unwrap();
      Ok(JsString::new(&mut cx, decrypted_string))
    },
    Err(_) => panic!("Failed to decrypt data")
  }
}

fn node_compact_sign_json(mut cx: FunctionContext) -> JsResult<JsString> {
  let alg = cx.argument::<JsNumber>(0)?;
  let payload = cx.argument::<JsString>(1)?;
  let jwk = cx.argument::<JsString>(2)?;

  // determine signing algorithm
  let signing_alg = match alg.value() as u8 {
    0 => SigningAlgorithm::Es256,
    1 => SigningAlgorithm::Es384,
    2 => SigningAlgorithm::Es512,
    3 => SigningAlgorithm::Es256k,
    4 => SigningAlgorithm::Eddsa,
    5 => SigningAlgorithm::Hs256,
    6 => SigningAlgorithm::Hs384,
    7 => SigningAlgorithm::Hs512,
    8 => SigningAlgorithm::Rs256,
    9 => SigningAlgorithm::Rs384,
    10 => SigningAlgorithm::Rs512,
    11 => SigningAlgorithm::Ps256,
    12 => SigningAlgorithm::Ps384,
    13 => SigningAlgorithm::Ps512,
    _ => panic!("Unsupported signing algorithm")
  };

  // convert serialised data to Jwk
  let signer_jwk: Jwk = serde_json::from_str(&jwk.value()).unwrap();

  // convert JsString to String
  let payload_string: String = payload.value();

  // sign message
  let signed = match rust_compact_sign_json(
    signing_alg,
    TokenType::DidcommSigned,
    payload_string.as_bytes(),
    &signer_jwk
  ) {
    Ok(signed) => signed,
    Err(_) => panic!("Failed to sign data")
  };

  Ok(JsString::new(&mut cx, signed))
}

fn node_compact_json_verify(mut cx: FunctionContext) -> JsResult<JsString> {
  let jws = cx.argument::<JsString>(0)?;
  let jwk_string = cx.argument::<JsString>(1)?;

  let jwk: Jwk = serde_json::from_str(&jwk_string.value()).unwrap();
  
  match rust_compact_json_verify(&jws.value(), &jwk) {
    Ok(verified) => {
      let ( payload, _header ) = verified;
      let payload_string = String::from_utf8(payload).unwrap();
      Ok(JsString::new(&mut cx, payload_string))
    },
    Err(_) => panic!("Failed to verify data")
  }
}

register_module!(mut cx, {
  cx.export_function("generate_key_pair_jwk", node_generate_key_pair_jwk)?;
  cx.export_function("generate_key_pair", node_generate_key_pair)?;
  cx.export_function("encrypt", node_encrypt)?;
  cx.export_function("decrypt", node_decrypt)?;
  cx.export_function("general_encrypt_json", node_general_encrypt_json)?;
  cx.export_function("decrypt_json", node_decrypt_json)?;
  cx.export_function("compact_sign_json", node_compact_sign_json)?;
  cx.export_function("compact_json_verify", node_compact_json_verify)?;
  Ok(())
});
