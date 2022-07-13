use josekit::{
  jwk::{
    alg::{
      ec::{EcCurve, EcKeyPair},
      ecx::{EcxCurve, EcxKeyPair},
      ed::{EdCurve, EdKeyPair}
    },
    Jwk,
  },
  jwe::{
    JweEncrypter,
    enc::{
      aesgcm::AesgcmJweEncryption,
      aescbc_hmac::AescbcHmacJweEncryption
    },
    alg::{
      direct::{DirectJweAlgorithm, DirectJweDecrypter},
      ecdh_es::{EcdhEsJweAlgorithm, EcdhEsJweDecrypter},
      rsaes::{RsaesJweAlgorithm, RsaesJweDecrypter},
      pbes2_hmac_aeskw::{Pbes2HmacAeskwJweAlgorithm, Pbes2HmacAeskwJweDecrypter},
      aeskw::{AeskwJweAlgorithm, AeskwJweDecrypter},
      aesgcmkw::{AesgcmkwJweAlgorithm, AesgcmkwJweDecrypter},
    },
    JweHeaderSet,
    JweHeader,
    serialize_general_json,
  },
  JoseError,
  // util::random_bytes
};

use serde::{Deserialize, Serialize};
use serde_json::{Value};
use std::fmt;
use base64;

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

#[allow(dead_code)]
#[repr(C)]
pub enum TokenType {
  DidcommPlain,
  DidcommSigned,
  DidcommEncrypted,
}

#[allow(dead_code)]
#[repr(C)]
pub enum KeyEncryptionAlgorithm {
  // Direct encryption
  Dir,
  // Diffie-Hellman
  EcdhEs,
  EcdhEsA128kw,
  EcdhEsA192kw,
  EcdhEsA256kw,
  // RSAES
  Rsa1_5,
  RsaOaep,
  RsaOaep256,
  RsaOaep384,
  RsaOaep512,
  // PBES2
  Pbes2Hs256A128kw,
  Pbes2Hs384A192kw,
  Pbes2Hs512A256kw,
  // AES Key Wrap
  A128kw,
  A192kw,
  A256kw,
  // AES GCM Key wrap
  A128gcmkw,
  A192gcmkw,
  A256gcmkw,
}

#[allow(dead_code)]
pub fn rust_general_encrypt_json(
  alg: KeyEncryptionAlgorithm,
  enc: ContentEncryptionAlgorithm,
  typ: TokenType,
  payload: &[u8],
  recipients: &[Jwk],
  aad: Option<&[u8]>
) -> Result<String, JoseError> {
  let token_type = match typ {
    TokenType::DidcommPlain => "application/didcomm-plain+json",
    TokenType::DidcommSigned => "application/didcomm-signed+json",
    TokenType::DidcommEncrypted => "application/didcomm-encrypted+json",
  };

  let key_encrypt_algorithm = match alg {
    // Direct encryption
    KeyEncryptionAlgorithm::Dir => "dir",
    // Diffie-Hellman
    KeyEncryptionAlgorithm::EcdhEs => "ECDH-ES",
    KeyEncryptionAlgorithm::EcdhEsA128kw => "ECDH-ES+A128KW",
    KeyEncryptionAlgorithm::EcdhEsA192kw => "ECDH-ES+A192KW",
    KeyEncryptionAlgorithm::EcdhEsA256kw => "ECDH-ES+A256KW",
    // RSAES
    KeyEncryptionAlgorithm::Rsa1_5 => "RSA1_5",
    KeyEncryptionAlgorithm::RsaOaep => "RSA-OAEP",
    KeyEncryptionAlgorithm::RsaOaep256 => "RSA-OAEP-256",
    KeyEncryptionAlgorithm::RsaOaep384 => "RSA-OAEP-384",
    KeyEncryptionAlgorithm::RsaOaep512 => "RSA-OAEP-512",
    // PBES2
    KeyEncryptionAlgorithm::Pbes2Hs256A128kw => "PBES2-HS256+A128KW",
    KeyEncryptionAlgorithm::Pbes2Hs384A192kw => "PBES2-HS384+A192KW",
    KeyEncryptionAlgorithm::Pbes2Hs512A256kw => "PBES2-HS512+A256KW",
    // AES Key Wrap
    KeyEncryptionAlgorithm::A128kw => "A128KW",
    KeyEncryptionAlgorithm::A192kw => "A192KW",
    KeyEncryptionAlgorithm::A256kw => "A256KW",
    // AES GCM Key wrap        
    KeyEncryptionAlgorithm::A128gcmkw => "A128GCMKW",
    KeyEncryptionAlgorithm::A192gcmkw => "A192GCMKW",
    KeyEncryptionAlgorithm::A256gcmkw => "A256GCMKW"
  };

  let content_encrypt_algorithm = match enc {
    // CBC encryption
    ContentEncryptionAlgorithm::A128cbcHs256 => "A128CBC-HS256",
    ContentEncryptionAlgorithm::A192cbcHs384 => "A192CBC-HS384",
    ContentEncryptionAlgorithm::A256cbcHs512 => "A256CBC-HS512",
    // GCM encryption
    ContentEncryptionAlgorithm::A128gcm => "A128GCM",
    ContentEncryptionAlgorithm::A192gcm => "A192GCM",
    ContentEncryptionAlgorithm::A256gcm => "A256GCM"
  };

  let mut header = JweHeaderSet::new();
  header.set_algorithm(key_encrypt_algorithm, true);
  header.set_content_encryption(content_encrypt_algorithm, true);
  header.set_token_type(token_type, true);

  let mut recipients_dir = Vec::new();
  let mut recipients_ecdhes = Vec::new();
  let mut recipients_rsaes = Vec::new();
  let mut recipients_pbes2 = Vec::new();
  let mut recipients_aeskw = Vec::new();
  let mut recipients_aesgcmkw = Vec::new();

  for i in 0..recipients.len() {
    let jwk = &recipients[i];
    let mut recipient_header = JweHeader::new();

    let kid = match jwk.key_id() {
      Some(kid) => kid,
      None => panic!("Key identifier (`kid`) required for jwk")
    };

    recipient_header.set_key_id(kid);

    match alg {
      // Direct encryption
      KeyEncryptionAlgorithm::Dir => recipients_dir.push((recipient_header, DirectJweAlgorithm::Dir.encrypter_from_jwk(jwk).unwrap())),
      // Diffie-Hellman
      KeyEncryptionAlgorithm::EcdhEs => recipients_ecdhes.push((recipient_header, EcdhEsJweAlgorithm::EcdhEs.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::EcdhEsA128kw => recipients_ecdhes.push((recipient_header, EcdhEsJweAlgorithm::EcdhEsA128kw.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::EcdhEsA192kw => recipients_ecdhes.push((recipient_header, EcdhEsJweAlgorithm::EcdhEsA192kw.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::EcdhEsA256kw => recipients_ecdhes.push((recipient_header, EcdhEsJweAlgorithm::EcdhEsA256kw.encrypter_from_jwk(jwk).unwrap())),
      // RSAES
      KeyEncryptionAlgorithm::Rsa1_5 => panic!("The `Rsa1_5` algorithm is no longer recommendeddur to a security vulnerability"),
      KeyEncryptionAlgorithm::RsaOaep => recipients_rsaes.push((recipient_header, RsaesJweAlgorithm::RsaOaep.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::RsaOaep256 => recipients_rsaes.push((recipient_header, RsaesJweAlgorithm::RsaOaep256.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::RsaOaep384 => recipients_rsaes.push((recipient_header, RsaesJweAlgorithm::RsaOaep384.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::RsaOaep512 => recipients_rsaes.push((recipient_header, RsaesJweAlgorithm::RsaOaep512.encrypter_from_jwk(jwk).unwrap())),
      // PBES2
      KeyEncryptionAlgorithm::Pbes2Hs256A128kw => recipients_pbes2.push((recipient_header, Pbes2HmacAeskwJweAlgorithm::Pbes2Hs256A128kw.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::Pbes2Hs384A192kw => recipients_pbes2.push((recipient_header, Pbes2HmacAeskwJweAlgorithm::Pbes2Hs384A192kw.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::Pbes2Hs512A256kw => recipients_pbes2.push((recipient_header, Pbes2HmacAeskwJweAlgorithm::Pbes2Hs512A256kw.encrypter_from_jwk(jwk).unwrap())),
      // AES Key Wrap
      KeyEncryptionAlgorithm::A128kw => recipients_aeskw.push((recipient_header, AeskwJweAlgorithm::A128kw.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::A192kw => recipients_aeskw.push((recipient_header, AeskwJweAlgorithm::A192kw.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::A256kw => recipients_aeskw.push((recipient_header, AeskwJweAlgorithm::A256kw.encrypter_from_jwk(jwk).unwrap())),
      // AES GCM Key wrap
      KeyEncryptionAlgorithm::A128gcmkw => recipients_aesgcmkw.push((recipient_header, AesgcmkwJweAlgorithm::A128gcmkw.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::A192gcmkw => recipients_aesgcmkw.push((recipient_header, AesgcmkwJweAlgorithm::A192gcmkw.encrypter_from_jwk(jwk).unwrap())),
      KeyEncryptionAlgorithm::A256gcmkw => recipients_aesgcmkw.push((recipient_header, AesgcmkwJweAlgorithm::A256gcmkw.encrypter_from_jwk(jwk).unwrap())),
    }
  }

  let mut recipients_combined = Vec::new();

  for i in 0..recipients_dir.len() {
    let (header, encrypter) = &recipients_dir[i];
    let encrypter_dir: &dyn JweEncrypter = encrypter;

    recipients_combined.push((Some(header), encrypter_dir));
  }

  for i in 0..recipients_ecdhes.len() {
    let (header, encrypter) = &recipients_ecdhes[i];
    let encrypter_ecdhes: &dyn JweEncrypter = encrypter;

    recipients_combined.push((Some(header), encrypter_ecdhes));
  }

  for i in 0..recipients_rsaes.len() {
    let (header, encrypter) = &recipients_rsaes[i];
    let encrypter_rsaes: &dyn JweEncrypter = encrypter;

    recipients_combined.push((Some(header), encrypter_rsaes));
  }

  for i in 0..recipients_pbes2.len() {
    let (header, encrypter) = &recipients_pbes2[i];
    let encrypter_pbes2: &dyn JweEncrypter = encrypter;

    recipients_combined.push((Some(header), encrypter_pbes2));
  }

  for i in 0..recipients_aeskw.len() {
    let (header, encrypter) = &recipients_aeskw[i];
    let encrypter_aeskw: &dyn JweEncrypter = encrypter;

    recipients_combined.push((Some(header), encrypter_aeskw));
  }

  for i in 0..recipients_aesgcmkw.len() {
    let (header, encrypter) = &recipients_aesgcmkw[i];
    let encrypter_aesgcmkw: &dyn JweEncrypter = encrypter;

    recipients_combined.push((Some(header), encrypter_aesgcmkw));
  }

  // encrypt payload & return encrypted string
  serialize_general_json(payload, Some(&header), recipients_combined.as_slice(), aad)
}
