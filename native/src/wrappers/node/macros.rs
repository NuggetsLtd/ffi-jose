macro_rules! arg_to_slice {
  ($cx:expr, $i:expr) => {{
      let arg: Handle<JsArrayBuffer> = $cx.argument::<JsArrayBuffer>($i)?;
      $cx.borrow(&arg, |d| d.as_slice::<u8>()).to_vec()
  }};
}
