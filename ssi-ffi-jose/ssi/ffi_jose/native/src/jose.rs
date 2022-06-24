use josekit::jwk::{
  alg::{ec::EcCurve, ecx::EcxCurve, ed::EdCurve},
  Jwk,
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
pub fn rust_generate_key_pair_jwk(named_curve: NamedCurve) -> String {
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
