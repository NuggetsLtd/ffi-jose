import { describe, it, expect } from "vitest";
import { compactJsonVerify, JWK } from "../src";
import jwks from "./jwks.json";

describe("jose", () => {
  describe("compactJsonVerify", () => {
    describe("should verify signed payload correctly", () => {
      describe("where alg type is `ECDSA`", () => {
        it("and `alg` = 'Es256'", async () => {
          const jws =
            "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYiLCJraWQiOiJkaWQ6bnVnZ2V0czpzWnppRnZkWHc4c2lNdmcxUDRZUzkxZ0c0TGMja2V5LXAyNTYtMSJ9.eyJoZWxsbyI6InRoZXJlIn0.BfEiEjO78RqBKDJ6CpgN-vIy7W7gBmDqKhXFXdN1E0XsgC4DxRJJwF4ThGVGBeMYPnJnIezIMfZl6fX94MEsxg";

          // @ts-ignore
          const jwk: JWK = jwks[0].public;

          const verified = await compactJsonVerify(jws, jwk);

          expect(verified).toEqual({ hello: "there" });
        });
      });
    });
  });
});
