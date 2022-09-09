import { generalSignJson, SigningAlgorithm, JWK } from "../src";
import jwks from './jwks.json';

describe("jose", () => {

  describe("generalSignJson", () => {
    const payload = { hello: 'there' };

    describe("should sign payload correctly", () => {

      it("with a single key", async () => {
        const alg = 'ES256';

        // @ts-ignore
        const signer_jwks: [JWK] = [ {
          ...jwks[0].private,
          alg
        } ];

        const signed = await generalSignJson(payload, signer_jwks);

        expect(signed.signatures.length).toBe(1);
        expect(signed.signatures[0].header.kid).toBe('did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1');
        expect(signed.signatures[0].protected).toBe('eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ');
        expect(signed.payload).toBe('eyJoZWxsbyI6InRoZXJlIn0');
      });

      it("with multiple keys of the same `alg` type", async () => {
        const alg = 'ES256';

        // @ts-ignore
        const signer_jwks: [JWK] = [ { ...jwks[0].private,  alg }, { ...jwks[1].private, alg } ];

        const signed = await generalSignJson(payload, signer_jwks);

        expect(signed.signatures.length).toBe(2);
        expect(signed.signatures[0].header.kid).toBe('did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1');
        expect(signed.signatures[0].protected).toBe('eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ');
        expect(signed.signatures[1].header.kid).toBe('did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p256-1');
        expect(signed.signatures[1].protected).toBe('eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ');
        expect(signed.payload).toBe('eyJoZWxsbyI6InRoZXJlIn0');
      });

      it("with multiple keys of different `alg` types", async () => {
        // @ts-ignore
        const signer_jwks: [JWK] = [ { ...jwks[0].private,  alg: 'ES256' }, { ...jwks[2].private, alg: 'ES512' } ];

        const signed = await generalSignJson(payload, signer_jwks);

        expect(signed.signatures.length).toBe(2);
        expect(signed.signatures[0].header.kid).toBe('did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1');
        expect(signed.signatures[0].protected).toBe('eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ');
        expect(signed.signatures[1].header.kid).toBe('did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p512-1');
        expect(signed.signatures[1].protected).toBe('eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVM1MTIifQ');
        expect(signed.payload).toBe('eyJoZWxsbyI6InRoZXJlIn0');
      });

    });

  });

});
