#include <stdio.h>
#include "libffi_jose.h"

int generate_key_pair(NamedCurve named_curve)
{
  JwkJsonString json_string;

  int outcome = generate_key_pair_jwk(named_curve, &json_string);

  if (outcome == 0)
  {
    printf("Generated JWK:\n%s\n\n", json_string.ptr);
  }

  free_jwk_string(json_string);
}

int main()
{
  generate_key_pair(P256);
  generate_key_pair(P384);
  generate_key_pair(P521);
  generate_key_pair(Secp256k1);
  generate_key_pair(Ed25519);
  generate_key_pair(Ed448);
  generate_key_pair(X25519);
  generate_key_pair(X448);
}
