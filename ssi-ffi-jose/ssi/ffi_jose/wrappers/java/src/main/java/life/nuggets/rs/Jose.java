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
      
      System.out.println("\nX448 (full key pair):");
      System.out.println(Jose.generate_key_pair(NamedCurve.X448.ordinal()));
      
      byte[] key = decodeHexString("b8aae648b9c7819e24f2b2c684efcef1");
      byte[] iv = decodeHexString("eae7e2df51f0dc34c39183e8");
      String msgString = "PLAINTEXT";
      byte[] msgBytes = msgString.getBytes();
      String aadString = "";
      byte[] aadBytes = aadString.getBytes();
      System.out.println("\nEncrypt:");
      System.out.println(Jose.encrypt(ContentEncryptionAlgorithm.A128gcm.ordinal(), key, iv, msgBytes, aadBytes));
  }
}
