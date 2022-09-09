import { flattenedSignJson, SigningAlgorithm, JWK } from "../src";
import jwks from './jwks.json';

describe("jose", () => {

  describe("flattenedSignJson", () => {
    const payload = { hello: 'there' };

    describe("should sign payload correctly", () => {

      describe("where alg type is `ECDSA`", () => {

        it("and `alg` = 'Es256'", async () => {
          const alg: SigningAlgorithm = SigningAlgorithm.Es256;

          // @ts-ignore
          const jwk: JWK = jwks[0].private;

          const signed = await flattenedSignJson(alg, payload, jwk);

          expect(signed.protected).toBe('eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ');
          expect(signed.header.kid).toBe('did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1');
          expect(signed.payload).toBe('eyJoZWxsbyI6InRoZXJlIn0');
        });

      });

    });

  });

});
