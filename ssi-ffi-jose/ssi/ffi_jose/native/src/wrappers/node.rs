use neon::prelude::*;
use crate::jose::{ NamedCurve, rust_generate_key_pair_jwk };

fn node_generate_key_pair_jwk(mut cx: FunctionContext) -> JsResult<JsString> {
  let options = cx.argument::<JsObject>(0)?;
  // let mut error = ExternError::success();

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

register_module!(mut cx, {
  cx.export_function("generate_key_pair_jwk", node_generate_key_pair_jwk)?;
  Ok(())
});
