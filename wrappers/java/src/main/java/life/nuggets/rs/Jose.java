package life.nuggets.rs;

class Jose {
  enum NamedCurve {
    P256,
    P384,
    P521,
    Secp256k1,
    Ed25519,
    Ed448,
    X25519,
    X448,
  }
  enum KeyEncryptionAlgorithm {
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
  enum ContentEncryptionAlgorithm {
    A128gcm,
    A192gcm,
    A256gcm,
    A128cbcHs256,
    A192cbcHs384,
    A256cbcHs512,
  }

  static {
      // This actually loads the shared object that we'll be creating.
      // The actual location of the .so or .dll may differ based on your
      // platform.
      System.loadLibrary("jose");
  }

  // Declare static methods provided by native library:
  private static native String generate_key_pair_jwk(int named_curve);
  private static native String generate_key_pair(int named_curve);
  private static native String encrypt(int enc, byte[] key, byte[] iv, byte[] message, byte[] aad);
  private static native String decrypt(int enc, byte[] key, byte[] ciphertext, byte[] iv, byte[] tag, byte[] aad);
  private static native String general_encrypt_json(int alg, int enc, byte[] payload, byte[] recipients);
  private static native String decrypt_json(byte[] jwe, byte[] jwk);

  public static byte hexToByte(String hexString) {
      int firstDigit = toDigit(hexString.charAt(0));
      int secondDigit = toDigit(hexString.charAt(1));
      return (byte) ((firstDigit << 4) + secondDigit);
  }

  private static int toDigit(char hexChar) {
      int digit = Character.digit(hexChar, 16);
      if(digit == -1) {
          throw new IllegalArgumentException(
            "Invalid Hexadecimal Character: "+ hexChar);
      }
      return digit;
  }

  public static byte[] decodeHexString(String hexString) {
      if (hexString.length() % 2 == 1) {
          throw new IllegalArgumentException(
            "Invalid hexadecimal String supplied.");
      }
      
      byte[] bytes = new byte[hexString.length() / 2];
      for (int i = 0; i < hexString.length(); i += 2) {
          bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
      }
      return bytes;
  }

  // The rest is just regular ol' Java!
  public static void main(String[] args) {
      // ----- Generate JWK -----------------------------------------------------------------------
      System.out.println("\nP-256:");
      System.out.println(Jose.generate_key_pair_jwk(NamedCurve.P256.ordinal()));
      
      System.out.println("\nP-384:");
      System.out.println(Jose.generate_key_pair_jwk(NamedCurve.P384.ordinal()));
      
      System.out.println("\nP-521:");
      System.out.println(Jose.generate_key_pair_jwk(NamedCurve.P521.ordinal()));
      
      System.out.println("\nsecp256k1:");
      System.out.println(Jose.generate_key_pair_jwk(NamedCurve.Secp256k1.ordinal()));
      
      System.out.println("\nEd25519:");
      System.out.println(Jose.generate_key_pair_jwk(NamedCurve.Ed25519.ordinal()));
      
      System.out.println("\nEd448:");
      System.out.println(Jose.generate_key_pair_jwk(NamedCurve.Ed448.ordinal()));
      
      System.out.println("\nX25519:");
      System.out.println(Jose.generate_key_pair_jwk(NamedCurve.X25519.ordinal()));
      
      System.out.println("\nX448:");
      System.out.println(Jose.generate_key_pair_jwk(NamedCurve.X448.ordinal()));
      
      // ----- Generate Keypair -------------------------------------------------------------------
      System.out.println("\nX448 (full key pair):");
      System.out.println(Jose.generate_key_pair(NamedCurve.X448.ordinal()));
      
      // ----- Encrypt & Decrypt ------------------------------------------------------------------
      byte[] key = decodeHexString("b8aae648b9c7819e24f2b2c684efcef1");
      byte[] iv = decodeHexString("eae7e2df51f0dc34c39183e8");
      String msgString = "PLAINTEXT";
      byte[] msgBytes = msgString.getBytes();
      String aadString = "";
      byte[] aadBytes = aadString.getBytes();
      
      System.out.println("\nEncrypt:");
      System.out.println(Jose.encrypt(ContentEncryptionAlgorithm.A128gcm.ordinal(), key, iv, msgBytes, aadBytes));

      byte[] ciphertext = decodeHexString("862dc0141058b5ca4768f7928a3c93fa35c6");
      byte[] tag = decodeHexString("aba4fd9f3ab9dde676f7b1a91f562b35");

      System.out.println("\nDecrypt:");
      System.out.println(Jose.decrypt(ContentEncryptionAlgorithm.A128gcm.ordinal(), key, ciphertext, iv, tag, aadBytes));

      // ----- JOSE Encrypt & Decrypt -------------------------------------------------------------
      String recipientsSingle = "[{\"kid\":\"did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"A4NKTvWeEv3b-sJnlmwrATDklidT_qo3jTYRV2shaAc\",\"y\":\"_06GxhBcbxJzOCTz4F0kq_mETgGti33WkFpMKZHc-SY\"}]";
      byte[] recipientsSingleBytes = recipientsSingle.getBytes();

      System.out.println("\nEncrypt JSON:");
      System.out.println(Jose.general_encrypt_json(KeyEncryptionAlgorithm.EcdhEsA128kw.ordinal(), ContentEncryptionAlgorithm.A128gcm.ordinal(), msgBytes, recipientsSingleBytes));

      String jwe1 = "{\"protected\":\"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkExMjhHQ00iLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0\",\"recipients\":[{\"header\":{\"kid\":\"did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1\",\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"gOck1VTJKClbIBckxyWDcvjgH7Hjh8l8JtZyMF_pcUg\",\"y\":\"erdiGdGNx_Bq3ZjIP0O6HqwnZ-hV4Qla1143vHg2CtA\"}},\"encrypted_key\":\"mYei_90yBUye5t54StnQWyZmpzgoaQ9N\"}],\"iv\":\"r7Tgd038slI_oE7v\",\"ciphertext\":\"0CPqmVTEOU3r\",\"tag\":\"WHzSP6R0tUK-w4UD1twngQ\"}";
      byte[] jwe1Bytes = jwe1.getBytes();
      String jwk1 = "{\"kid\":\"did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"qjx4ib5Ea94YnyypBBPnvtGUuoRgGtF_0BtPuOSMJPc\"}";
      byte[] jwk1Bytes = jwk1.getBytes();

      System.out.println("\nDecrypt JSON:");
      System.out.println(Jose.decrypt_json(jwe1Bytes, jwk1Bytes));
  }
}
