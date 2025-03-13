import { describe, it, expect } from "vitest";
import { NamedCurve, generateJWK, JoseGenerateJwkRequest } from "../src";

describe("jose", () => {
  describe("generateJWK", () => {
    describe("should generate a valid JWK", () => {
      it("where `namedCurve` = 'P256'", async () => {
        const request: JoseGenerateJwkRequest = {
          namedCurve: NamedCurve.P256,
        };

        const jwk = await generateJWK(request);

        expect(jwk).toBeInstanceOf(Object);
        expect(Object.keys(jwk).sort()).toEqual(["crv", "d", "kty", "x", "y"]);
        expect(jwk.kty).toEqual("EC");
        expect(jwk.crv).toEqual("P-256");
        expect(Buffer.from(jwk.d!, "base64").length).toBe(32);
        expect(Buffer.from(jwk.x!, "base64").length).toBe(32);
        expect(Buffer.from(jwk.y!, "base64").length).toBe(32);
      });

      it("where `namedCurve` = 'P384'", async () => {
        const request: JoseGenerateJwkRequest = {
          namedCurve: NamedCurve.P384,
        };

        const jwk = await generateJWK(request);

        expect(jwk).toBeInstanceOf(Object);
        expect(Object.keys(jwk).sort()).toEqual(["crv", "d", "kty", "x", "y"]);
        expect(jwk.kty).toEqual("EC");
        expect(jwk.crv).toEqual("P-384");
        expect(Buffer.from(jwk.d!, "base64").length).toBe(48);
        expect(Buffer.from(jwk.x!, "base64").length).toBe(48);
        expect(Buffer.from(jwk.y!, "base64").length).toBe(48);
      });

      it("where `namedCurve` = 'P521'", async () => {
        const request: JoseGenerateJwkRequest = {
          namedCurve: NamedCurve.P521,
        };

        const jwk = await generateJWK(request);

        expect(jwk).toBeInstanceOf(Object);
        expect(Object.keys(jwk).sort()).toEqual(["crv", "d", "kty", "x", "y"]);
        expect(jwk.kty).toEqual("EC");
        expect(jwk.crv).toEqual("P-521");
        expect(Buffer.from(jwk.d!, "base64").length).toBe(66);
        expect(Buffer.from(jwk.x!, "base64").length).toBe(66);
        expect(Buffer.from(jwk.y!, "base64").length).toBe(66);
      });

      it("where `namedCurve` = 'secp256k1'", async () => {
        const request: JoseGenerateJwkRequest = {
          namedCurve: NamedCurve.Secp256k1,
        };

        const jwk = await generateJWK(request);

        expect(jwk).toBeInstanceOf(Object);
        expect(Object.keys(jwk).sort()).toEqual(["crv", "d", "kty", "x", "y"]);
        expect(jwk.kty).toEqual("EC");
        expect(jwk.crv).toEqual("secp256k1");
        expect(Buffer.from(jwk.d!, "base64").length).toBe(32);
        expect(Buffer.from(jwk.x!, "base64").length).toBe(32);
        expect(Buffer.from(jwk.y!, "base64").length).toBe(32);
      });

      it("where `namedCurve` = 'Ed25519'", async () => {
        const request: JoseGenerateJwkRequest = {
          namedCurve: NamedCurve.Ed25519,
        };

        const jwk = await generateJWK(request);

        expect(jwk).toBeInstanceOf(Object);
        expect(Object.keys(jwk).sort()).toEqual(["crv", "d", "kty", "use", "x"]);
        expect(jwk.kty).toEqual("OKP");
        expect(jwk.crv).toEqual("Ed25519");
        expect(jwk.use).toEqual("sig");
        expect(Buffer.from(jwk.d!, "base64").length).toBe(32);
        expect(Buffer.from(jwk.x!, "base64").length).toBe(32);
      });

      it("where `namedCurve` = 'Ed448'", async () => {
        const request: JoseGenerateJwkRequest = {
          namedCurve: NamedCurve.Ed448,
        };

        const jwk = await generateJWK(request);

        expect(jwk).toBeInstanceOf(Object);
        expect(Object.keys(jwk).sort()).toEqual(["crv", "d", "kty", "use", "x"]);
        expect(jwk.kty).toEqual("OKP");
        expect(jwk.crv).toEqual("Ed448");
        expect(jwk.use).toEqual("sig");
        expect(Buffer.from(jwk.d!, "base64").length).toBe(57);
        expect(Buffer.from(jwk.x!, "base64").length).toBe(57);
      });

      it("where `namedCurve` = 'X25519'", async () => {
        const request: JoseGenerateJwkRequest = {
          namedCurve: NamedCurve.X25519,
        };

        const jwk = await generateJWK(request);

        expect(jwk).toBeInstanceOf(Object);
        expect(Object.keys(jwk).sort()).toEqual(["crv", "d", "kty", "use", "x"]);
        expect(jwk.kty).toEqual("OKP");
        expect(jwk.crv).toEqual("X25519");
        expect(jwk.use).toEqual("enc");
        expect(Buffer.from(jwk.d!, "base64").length).toBe(32);
        expect(Buffer.from(jwk.x!, "base64").length).toBe(32);
      });

      it("where `namedCurve` = 'X448'", async () => {
        const request: JoseGenerateJwkRequest = {
          namedCurve: NamedCurve.X448,
        };

        const jwk = await generateJWK(request);

        expect(jwk).toBeInstanceOf(Object);
        expect(Object.keys(jwk).sort()).toEqual(["crv", "d", "kty", "use", "x"]);
        expect(jwk.kty).toEqual("OKP");
        expect(jwk.crv).toEqual("X448");
        expect(jwk.use).toEqual("enc");
        expect(Buffer.from(jwk.d!, "base64").length).toBe(56);
        expect(Buffer.from(jwk.x!, "base64").length).toBe(56);
      });
    });
  });
});
