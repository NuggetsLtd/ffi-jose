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

  // This declares that the static `hello` method will be provided
  // a native library.
  private static native String generate_key_pair_jwk(int named_curve);

  static {
      // This actually loads the shared object that we'll be creating.
      // The actual location of the .so or .dll may differ based on your
      // platform.
      System.loadLibrary("jose");
  }

  // Declare static methods provided by native library:
  private static native String generate_key_pair_jwk(int named_curve);
  private static native String generate_key_pair(int named_curve);
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
  }
}
