import { generalSignJson, SigningAlgorithm, JWK } from "../src";
import jwks from './jwks.json';

describe("jose", () => {

  describe("generalSignJson", () => {
    const payload = { hello: 'there' };

    describe("should sign payload correctly", () => {

      describe("where alg type is `ECDSA`", () => {

        it("and `alg` = 'Es256'", async () => {
          const alg: SigningAlgorithm = SigningAlgorithm.Es256;

          // @ts-ignore
          const signer_jwks: [JWK] = [ jwks[0].private, jwks[1].private ];

          const signed = await generalSignJson(alg, payload, signer_jwks);

          expect(signed.signatures.length).toBe(2);
          expect(signed.signatures[0].header.kid).toBe('did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1');
          expect(signed.signatures[0].protected).toBe('eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ');
          expect(signed.signatures[1].header.kid).toBe('did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p256-1');
          expect(signed.signatures[1].protected).toBe('eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ');
          expect(signed.payload).toBe('eyJoZWxsbyI6InRoZXJlIn0');
        });

      });

    });

  });

});
