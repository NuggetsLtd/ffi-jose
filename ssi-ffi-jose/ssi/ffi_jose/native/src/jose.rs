use josekit::{
  jwk::{
    alg::{ec::EcCurve, ecx::EcxCurve, ed::EdCurve},
    Jwk,
  },
  jwe::{
    enc::{
      aesgcm::AesgcmJweEncryption,
      aescbc_hmac::AescbcHmacJweEncryption
    }
  },
  JoseError,
  // util::random_bytes
};

use serde_json;
use std::fmt;

#[allow(dead_code)]
#[repr(C)]
pub enum NamedCurve {
  // EC curves
  P256,
  P384,
  P521,
  Secp256k1,
  // ED curves
  Ed25519,
  Ed448,
  // ECX curves
  X25519,
  X448,
}

impl fmt::Display for NamedCurve {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      NamedCurve::P256 => write!(f, "({})", "P-256"),
      NamedCurve::P384 => write!(f, "({})", "P-384"),
      NamedCurve::P521 => write!(f, "({})", "P-521"),
      NamedCurve::Secp256k1 => write!(f, "({})", "secp256k1"),
      NamedCurve::Ed25519 => write!(f, "({})", "Ed25519"),
      NamedCurve::Ed448 => write!(f, "({})", "Ed448"),
      NamedCurve::X25519 => write!(f, "({})", "X25519"),
      NamedCurve::X448 => write!(f, "({})", "X448"),
    }
  }
}

impl fmt::Debug for NamedCurve {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      NamedCurve::P256 => write!(f, "({})", "P-256"),
      NamedCurve::P384 => write!(f, "({})", "P-384"),
      NamedCurve::P521 => write!(f, "({})", "P-521"),
      NamedCurve::Secp256k1 => write!(f, "({})", "secp256k1"),
      NamedCurve::Ed25519 => write!(f, "({})", "Ed25519"),
      NamedCurve::Ed448 => write!(f, "({})", "Ed448"),
      NamedCurve::X25519 => write!(f, "({})", "X25519"),
      NamedCurve::X448 => write!(f, "({})", "X448"),
    }
  }
}

#[allow(dead_code)]
pub fn rust_generate_key_pair_jwk(
  named_curve: NamedCurve
) -> String {
  let mut ec_named_curve: Option<EcCurve> = None;
  let mut ed_named_curve: Option<EdCurve> = None;
  let mut ecx_named_curve: Option<EcxCurve> = None;
  let mut generated_jwk: Option<Jwk> = None;

  match named_curve {
    // EC curves
    NamedCurve::P256 => ec_named_curve = Some(EcCurve::P256),
    NamedCurve::P384 => ec_named_curve = Some(EcCurve::P384),
    NamedCurve::P521 => ec_named_curve = Some(EcCurve::P521),
    NamedCurve::Secp256k1 => ec_named_curve = Some(EcCurve::Secp256k1),
    // ED curves
    NamedCurve::Ed25519 => ed_named_curve =  Some(EdCurve::Ed25519),
    NamedCurve::Ed448 => ed_named_curve =  Some(EdCurve::Ed448),
    // ECX curves
    NamedCurve::X25519 => ecx_named_curve =  Some(EcxCurve::X25519),
    NamedCurve::X448 => ecx_named_curve =  Some(EcxCurve::X448),
  }

  match ec_named_curve {
    Some(a) => {
      match Jwk::generate_ec_key(a) {
        Ok(jwk) => generated_jwk = Some(jwk),
        Err(_) => panic!("Unable to generate EC keypair for curve: {}", named_curve)
      };
    },
    None => ()
  }

  match ed_named_curve {
    Some(a) => {
      match Jwk::generate_ed_key(a) {
        Ok(jwk) => generated_jwk = Some(jwk),
        Err(_) => panic!("Unable to generate ED keypair for curve: {}", named_curve)
      };
    },
    None => ()
  }

  match ecx_named_curve {
    Some(a) => {
      match Jwk::generate_ecx_key(a) {
        Ok(jwk) => generated_jwk = Some(jwk),
        Err(_) => panic!("Unable to generate ECX keypair for curve: {:?}", named_curve)
      };
    },
    None => ()
  }

  // Serialize JWK to a JSON string
  let jwk_cstring: String = match serde_json::to_string(&generated_jwk) {
    Ok(jwk) => String::from(jwk),
    Err(_) => panic!("Unable to serialise JWK to JSON string")
  };

  jwk_cstring
}

#[derive(Serialize, Deserialize)]
struct KeyPair {
  jwk_key_pair: Jwk,
  jwk_private_key: Jwk,
  jwk_public_key: Jwk,
  pem_private_key: String,
  pem_public_key: String,
  der_private_key: String,
  der_public_key: String,
}

#[allow(dead_code)]
pub fn rust_generate_key_pair(
  named_curve: NamedCurve
) -> String {
  let mut ec_named_curve: Option<EcCurve> = None;
  let mut ed_named_curve: Option<EdCurve> = None;
  let mut ecx_named_curve: Option<EcxCurve> = None;
  let mut key_pair: Option<KeyPair> = None;

  match named_curve {
    // EC curves
    NamedCurve::P256 => ec_named_curve = Some(EcCurve::P256),
    NamedCurve::P384 => ec_named_curve = Some(EcCurve::P384),
    NamedCurve::P521 => ec_named_curve = Some(EcCurve::P521),
    NamedCurve::Secp256k1 => ec_named_curve = Some(EcCurve::Secp256k1),
    // ED curves
    NamedCurve::Ed25519 => ed_named_curve =  Some(EdCurve::Ed25519),
    NamedCurve::Ed448 => ed_named_curve =  Some(EdCurve::Ed448),
    // ECX curves
    NamedCurve::X25519 => ecx_named_curve =  Some(EcxCurve::X25519),
    NamedCurve::X448 => ecx_named_curve =  Some(EcxCurve::X448),
  }

  match ec_named_curve {
    Some(curve) => {
      match EcKeyPair::generate(curve) {
        Ok(ec_key_pair) =>{
          key_pair = Some(KeyPair {
            jwk_key_pair: ec_key_pair.to_jwk_key_pair(),
            jwk_private_key: ec_key_pair.to_jwk_private_key(),
            jwk_public_key: ec_key_pair.to_jwk_public_key(),
            pem_private_key: base64::encode(ec_key_pair.to_pem_private_key()),
            pem_public_key: base64::encode(ec_key_pair.to_pem_public_key()),
            der_private_key: base64::encode(ec_key_pair.to_der_private_key()),
            der_public_key: base64::encode(ec_key_pair.to_der_public_key()),
          });
        },
        Err(_) => panic!("Unable to generate EC keypair for curve: {}", named_curve)
      };
    },
    None => ()
  }

  match ed_named_curve {
    Some(curve) => {
      match EdKeyPair::generate(curve) {
        Ok(ed_key_pair) => {
          key_pair = Some(KeyPair {
            jwk_key_pair: ed_key_pair.to_jwk_key_pair(),
            jwk_private_key: ed_key_pair.to_jwk_private_key(),
            jwk_public_key: ed_key_pair.to_jwk_public_key(),
            pem_private_key: base64::encode(ed_key_pair.to_pem_private_key()),
            pem_public_key: base64::encode(ed_key_pair.to_pem_public_key()),
            der_private_key: base64::encode(ed_key_pair.to_der_private_key()),
            der_public_key: base64::encode(ed_key_pair.to_der_public_key()),
          });
        },
        Err(_) => panic!("Unable to generate ED keypair for curve: {}", named_curve)
      };
    },
    None => ()
  }

  match ecx_named_curve {
    Some(curve) => {
      match EcxKeyPair::generate(curve) {
        Ok(ecx_key_pair) => {
          key_pair = Some(KeyPair {
            jwk_key_pair: ecx_key_pair.to_jwk_key_pair(),
            jwk_private_key: ecx_key_pair.to_jwk_private_key(),
            jwk_public_key: ecx_key_pair.to_jwk_public_key(),
            pem_private_key: base64::encode(ecx_key_pair.to_pem_private_key()),
            pem_public_key: base64::encode(ecx_key_pair.to_pem_public_key()),
            der_private_key: base64::encode(ecx_key_pair.to_der_private_key()),
            der_public_key: base64::encode(ecx_key_pair.to_der_public_key()),
          });
        },
        Err(_) => panic!("Unable to generate ECX keypair for curve: {:?}", named_curve)
      };
    },
    None => ()
  }

  // Serialize JWK to a JSON string
  let json_cstring: String = match serde_json::to_string(&key_pair) {
    Ok(json) => String::from(json),
    Err(_) => panic!("Unable to serialise Key Pair to JSON string")
  };

  json_cstring
}

#[allow(dead_code)]
#[repr(C)]
pub enum ContentEncryptionAlgorithm {
  A128gcm,
  A192gcm,
  A256gcm,
  A128cbcHs256,
  A192cbcHs384,
  A256cbcHs512,
}

#[allow(dead_code)]
pub fn rust_encrypt(
  enc: ContentEncryptionAlgorithm,
  key: &[u8],
  iv: &[u8],
  message: &[u8],
  aad: &[u8]
) -> Result<(Vec<u8>, Option<Vec<u8>>), JoseError> {
  let mut enc_aesgcm: Option<AesgcmJweEncryption> = None;
  let mut enc_aescbc_hmac: Option<AescbcHmacJweEncryption> = None;
  let mut encrypted: Option<Result<(Vec<u8>, Option<Vec<u8>>), JoseError>> = None;

  match enc {
    // GCM encryption
    ContentEncryptionAlgorithm::A128gcm => enc_aesgcm = Some(AesgcmJweEncryption::A128gcm),
    ContentEncryptionAlgorithm::A192gcm => enc_aesgcm = Some(AesgcmJweEncryption::A192gcm),
    ContentEncryptionAlgorithm::A256gcm => enc_aesgcm = Some(AesgcmJweEncryption::A256gcm),
    // CBC encryption
    ContentEncryptionAlgorithm::A128cbcHs256 => enc_aescbc_hmac = Some(AescbcHmacJweEncryption::A128cbcHs256),
    ContentEncryptionAlgorithm::A192cbcHs384 => enc_aescbc_hmac = Some(AescbcHmacJweEncryption::A192cbcHs384),
    ContentEncryptionAlgorithm::A256cbcHs512 => enc_aescbc_hmac = Some(AescbcHmacJweEncryption::A256cbcHs512),
  };

  match enc_aesgcm {
    Some(encryptor) => {
      if key.len() != encryptor.key_len() {
        panic!("Expected Key length of {}, received {}", encryptor.key_len(), key.len());
      }
    
      if iv.len() != encryptor.iv_len() {
        panic!("Expected IV length of {}, received {}", encryptor.iv_len(), iv.len());
      }
    
      encrypted = Some(encryptor.encrypt(
        key,
        Some(iv),
        message,
        aad
      ));
    },
    None => ()
  };

  match enc_aescbc_hmac {
    Some(encryptor) => {
      if key.len() != encryptor.key_len() {
        panic!("Expected Key length of {}, received {}", encryptor.key_len(), key.len());
      }
    
      if iv.len() != encryptor.iv_len() {
        panic!("Expected IV length of {}, received {}", encryptor.iv_len(), iv.len());
      }
    
      encrypted = Some(encryptor.encrypt(
        key,
        Some(iv),
        message,
        aad
      ));
    },
    None => ()
  };

  encrypted.unwrap()
}

#[allow(dead_code)]
pub fn rust_decrypt(
  enc: ContentEncryptionAlgorithm,
  key: &[u8],
  ciphertext: &[u8],
  iv: &[u8],
  tag: &[u8],
  aad: &[u8]
) -> Result<Vec<u8>, JoseError> {
  let mut enc_aesgcm: Option<AesgcmJweEncryption> = None;
  let mut enc_aescbc_hmac: Option<AescbcHmacJweEncryption> = None;
  let mut decrypted: Option<Result<Vec<u8>, JoseError>> = None;

  match enc {
    // GCM encryption
    ContentEncryptionAlgorithm::A128gcm => enc_aesgcm = Some(AesgcmJweEncryption::A128gcm),
    ContentEncryptionAlgorithm::A192gcm => enc_aesgcm = Some(AesgcmJweEncryption::A192gcm),
    ContentEncryptionAlgorithm::A256gcm => enc_aesgcm = Some(AesgcmJweEncryption::A256gcm),
    // CBC encryption
    ContentEncryptionAlgorithm::A128cbcHs256 => enc_aescbc_hmac = Some(AescbcHmacJweEncryption::A128cbcHs256),
    ContentEncryptionAlgorithm::A192cbcHs384 => enc_aescbc_hmac = Some(AescbcHmacJweEncryption::A192cbcHs384),
    ContentEncryptionAlgorithm::A256cbcHs512 => enc_aescbc_hmac = Some(AescbcHmacJweEncryption::A256cbcHs512),
  };

  match enc_aesgcm {
    Some(decryptor) => {
      if key.len() != decryptor.key_len() {
        panic!("Expected Key length of {}, received {}", decryptor.key_len(), key.len());
      }
    
      if iv.len() != decryptor.iv_len() {
        panic!("Expected IV length of {}, received {}", decryptor.iv_len(), iv.len());
      }
    
      decrypted = Some(decryptor.decrypt(
        key,
        Some(iv),
        ciphertext,
        aad,
        Some(tag),
      ));
    },
    None => ()
  };

  match enc_aescbc_hmac {
    Some(decryptor) => {
      if key.len() != decryptor.key_len() {
        panic!("Expected Key length of {}, received {}", decryptor.key_len(), key.len());
      }
    
      if iv.len() != decryptor.iv_len() {
        panic!("Expected IV length of {}, received {}", decryptor.iv_len(), iv.len());
      }
    
      decrypted = Some(decryptor.decrypt(
        key,
        Some(iv),
        ciphertext,
        aad,
        Some(tag),
      ));
    },
    None => ()
  };

  decrypted.unwrap()
}
