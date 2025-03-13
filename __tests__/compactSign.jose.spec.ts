import { describe, it, expect } from "vitest";
import { compactSignJson, SigningAlgorithm, JWK } from "../src";
import jwks from "./jwks.json";

describe("jose", () => {
  describe("compactSignJson", () => {
    const payload = { hello: "there" };

    describe("should sign payload correctly", () => {
      describe("where alg type is `ECDSA`", () => {
        describe("and `alg` = 'Es256'", () => {
          it("and didcomm = true", async () => {
            const alg: SigningAlgorithm = SigningAlgorithm.Es256;

            // @ts-ignore
            const jwk: JWK = jwks[0].private;

            const signed = await compactSignJson(alg, payload, jwk, true);

            const [protected_b64, payload_b64] = signed.split(".");

            expect(protected_b64).toBe(
              "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYiLCJraWQiOiJkaWQ6bnVnZ2V0czpzWnppRnZkWHc4c2lNdmcxUDRZUzkxZ0c0TGMja2V5LXAyNTYtMSJ9"
            );
            expect(payload_b64).toBe("eyJoZWxsbyI6InRoZXJlIn0");
          });

          it("and didcomm = false (default)", async () => {
            const alg: SigningAlgorithm = SigningAlgorithm.Es256;

            // @ts-ignore
            const jwk: JWK = jwks[0].private;

            const signed = await compactSignJson(alg, payload, jwk);

            const [protected_b64, payload_b64] = signed.split(".");

            expect(protected_b64).toBe(
              "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpudWdnZXRzOnNaemlGdmRYdzhzaU12ZzFQNFlTOTFnRzRMYyNrZXktcDI1Ni0xIn0"
            );
            expect(payload_b64).toBe("eyJoZWxsbyI6InRoZXJlIn0");
          });
        });
      });
    });
  });
});
