import { KeyEncryption, ContentEncryption, JWK } from "../src";
import { generalEncryptJson } from "../src";

const base64ToArrayBuffer = (value: string) => Uint8Array.from(Buffer.from(value, "base64"));

const jwks: { public: JWK; private: JWK }[] = [
  {
    public: {
      kid: "did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1",
      kty: "EC",
      crv: "P-256",
      x: "A4NKTvWeEv3b-sJnlmwrATDklidT_qo3jTYRV2shaAc",
      y: "_06GxhBcbxJzOCTz4F0kq_mETgGti33WkFpMKZHc-SY",
    },
    private: {
      kid: "did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1",
      kty: "EC",
      crv: "P-256",
      d: "qjx4ib5Ea94YnyypBBPnvtGUuoRgGtF_0BtPuOSMJPc",
    },
  },
  {
    public: {
      kid: "did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p256-1",
      kty: "EC",
      crv: "P-256",
      x: "YQbhZhp4ORKjwMqQIGFbIVSyYaaBuJbym_UWEWJPgbM",
      y: "hxHEiOwPXUt1Nv_3MO5oRkUoMtYFaWIzW0iiZMNTnFE",
    },
    private: {
      kid: "did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p256-1",
      kty: "EC",
      crv: "P-256",
      d: "pndx4RjZSMpYjkokcn5xcIfmhZV19-jr_0n4l1kcphI",
    },
  },
];

describe("jose", () => {
  describe("generalEncryptJson()", () => {
    const payload = {
      hello: "there",
    };
    const aad = base64ToArrayBuffer("");

    describe("should encrypt plaintext correctly", () => {

      describe("where enc type is `GCM`", () => {

        describe('and didcomm = true', () => {

          it("and `enc` = 'A128GCM'", async () => {
            const alg = KeyEncryption.EcdhEsA128kw;
            const enc = ContentEncryption.A128gcm;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients, true);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhHQ00iLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });
  
          it("and `enc` = 'A192GCM'", async () => {
            const alg = KeyEncryption.EcdhEsA192kw;
            const enc = ContentEncryption.A192gcm;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients, true);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0ExOTJLVyIsImVuYyI6IkExOTJHQ00iLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });
  
          it("and `enc` = 'A256GCM'", async () => {
            const alg = KeyEncryption.EcdhEsA256kw;
            const enc = ContentEncryption.A256gcm;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients, true);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });

        })

        describe('and didcomm = false (default)', () => {

          it("and `enc` = 'A128GCM'", async () => {
            const alg = KeyEncryption.EcdhEsA128kw;
            const enc = ContentEncryption.A128gcm;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhHQ00iLCJ0eXAiOiJKV1QifQ"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });
  
          it("and `enc` = 'A192GCM'", async () => {
            const alg = KeyEncryption.EcdhEsA192kw;
            const enc = ContentEncryption.A192gcm;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0ExOTJLVyIsImVuYyI6IkExOTJHQ00iLCJ0eXAiOiJKV1QifQ"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });
  
          it("and `enc` = 'A256GCM'", async () => {
            const alg = KeyEncryption.EcdhEsA256kw;
            const enc = ContentEncryption.A256gcm;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJ0eXAiOiJKV1QifQ"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });

        })

      });

      describe("where enc type is `CBC`", () => {

        describe('and didcomm = true', () => {

          it("and enc=`A128CBC-HS256`", async () => {
            const alg = KeyEncryption.EcdhEsA128kw;
            const enc = ContentEncryption.A128cbcHs256;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients, true);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });
  
          it("and enc=`A192CBC-HS384`", async () => {
            const alg = KeyEncryption.EcdhEsA192kw;
            const enc = ContentEncryption.A192cbcHs384;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients, true);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0ExOTJLVyIsImVuYyI6IkExOTJDQkMtSFMzODQiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });
  
          it("and enc=`A256CBC-HS512`", async () => {
            const alg = KeyEncryption.EcdhEsA256kw;
            const enc = ContentEncryption.A256cbcHs512;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients, true);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });

        })

        describe('and didcomm = false (default)', () => {

          it("and enc=`A128CBC-HS256`", async () => {
            const alg = KeyEncryption.EcdhEsA128kw;
            const enc = ContentEncryption.A128cbcHs256;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJ0eXAiOiJKV1QifQ"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });
  
          it("and enc=`A192CBC-HS384`", async () => {
            const alg = KeyEncryption.EcdhEsA192kw;
            const enc = ContentEncryption.A192cbcHs384;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0ExOTJLVyIsImVuYyI6IkExOTJDQkMtSFMzODQiLCJ0eXAiOiJKV1QifQ"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });
  
          it("and enc=`A256CBC-HS512`", async () => {
            const alg = KeyEncryption.EcdhEsA256kw;
            const enc = ContentEncryption.A256cbcHs512;
            const recipients: JWK[] = [jwks[0].public];
  
            const jwe = await generalEncryptJson(alg, enc, payload, recipients);
  
            expect(jwe).toBeInstanceOf(Object);
            expect(Object.keys(jwe).sort()).toEqual(["ciphertext", "iv", "protected", "recipients", "tag"]);
            expect(jwe.protected).toEqual(
              "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJ0eXAiOiJKV1QifQ"
            );
            expect(jwe.recipients[0].header.kid).toBe(jwks[0].public.kid);
          });

        })

      });

    });

  });

});
