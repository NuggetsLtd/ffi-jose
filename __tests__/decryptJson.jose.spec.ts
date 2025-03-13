import { describe, it, expect } from "vitest";
import { KeyEncryption, ContentEncryption, JWK } from "../src";
import { generalEncryptJson, decryptJson } from "../src";

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
  describe("decryptJson()", () => {
    const payload = {
      hello: "there",
    };

    describe("should decrypt JWE correctly", () => {
      describe("where enc type is `GCM`", () => {
        it("and `enc` = 'A128GCM'", async () => {
          const jwe = {
            protected:
              "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhHQ00iLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0",
            recipients: [
              {
                header: {
                  kid: "did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1",
                  epk: {
                    kty: "EC",
                    crv: "P-256",
                    x: "dLXv8shsQ4Po2rSdQrA4AmBlVv5nMnlSzB-IdwonJOo",
                    y: "8fqS8oUc26f0GxoQsvVQJortYYMoCGKQcdH7vj8qbPE",
                  },
                },
                encrypted_key: "-VfEFi1uJQ2kSrYKWOIkMZq_xCR0cX2E",
              },
            ],
            iv: "uQ5mIBqYE5IQn_u7",
            ciphertext: "RmDmVCiG01FRWaO01ocDdbo",
            tag: "S9IqzCGME4pZG-7onvbI1w",
          };

          const json = await decryptJson(jwe, jwks[0].private);

          expect(json).toEqual(payload);
        });

        it("and `enc` = 'A192GCM'", async () => {
          const jwe = {
            protected:
              "eyJhbGciOiJFQ0RILUVTK0ExOTJLVyIsImVuYyI6IkExOTJHQ00iLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0",
            recipients: [
              {
                header: {
                  kid: "did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1",
                  epk: {
                    kty: "EC",
                    crv: "P-256",
                    x: "uZC0_hMxC5jyFISVGTIhi6PdOTEIre-Sxdb98Jx5qfA",
                    y: "wrsyfJxywkcNf77QlHjGEkN0mM2eAan9dJvf5aQrqfU",
                  },
                },
                encrypted_key: "W3kA2xIv9nVe4doi_kRlPKLiPWb7KhngSomP-JaoSnU",
              },
            ],
            iv: "2FfZqt5bEEvgYDkI",
            ciphertext: "iCBPN7BIhGPuJiK321cVDi8",
            tag: "X8sCf5f1uy_xVm1SXtbqpQ",
          };

          const json = await decryptJson(jwe, jwks[0].private);

          expect(json).toEqual(payload);
        });

        it("and `enc` = 'A256GCM'", async () => {
          const jwe = {
            protected:
              "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0",
            recipients: [
              {
                header: {
                  kid: "did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1",
                  epk: {
                    kty: "EC",
                    crv: "P-256",
                    x: "iBXylmryYobqz1joDrUo_J3WnuE8w3i9NtvxQn5rQ0g",
                    y: "J8Z6BqYsn2IGezsvnAU-9UbRDfQAE4C-v3RVOUDpQjM",
                  },
                },
                encrypted_key: "9LnXH8ojM8SR6iC9O7nDvcrBgmDiGNw34Na1icrQKp2HW4XB3QMcxg",
              },
            ],
            iv: "Ejosy9O6J9kUiop-",
            ciphertext: "v9EBTqcjGCQzSPBaOprZNvE",
            tag: "NlVCqoiL5BieR6n_nFehYQ",
          };

          const json = await decryptJson(jwe, jwks[0].private);

          expect(json).toEqual(payload);
        });
      });

      describe("where enc type is `CBC`", () => {
        const iv = Uint8Array.from(Buffer.from("5ee779854f0e37e83f39441c86cebe90", "hex"));

        it("and enc=`A128CBC-HS256`", async () => {
          const jwe = {
            protected:
              "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0",
            recipients: [
              {
                header: {
                  kid: "did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1",
                  epk: {
                    kty: "EC",
                    crv: "P-256",
                    x: "0sy-j1fcjiF2oF-K1eE94ebnElf8ZjgAbWZd2a478rk",
                    y: "r8uVhykcgVMFSrBse-3nufOVvDGR3hW84OjXYtmtYpM",
                  },
                },
                encrypted_key: "XGUlyPhkp9FWW-Ypk0zce-BAMtW_Y6BLGGPKe7nIkq0mDfSG7BzBaA",
              },
            ],
            iv: "tLJWqXnx5cOQXZUDqaVUlQ",
            ciphertext: "nmmTq263Fy7u1Bh64aucyp77Hj4teLN1GNdknLSMlts",
            tag: "PT4GJqsOwpXHecfcSK_UNw",
          };

          const json = await decryptJson(jwe, jwks[0].private);

          expect(json).toEqual(payload);
        });

        it("and enc=`A192CBC-HS384`", async () => {
          const jwe = {
            protected:
              "eyJhbGciOiJFQ0RILUVTK0ExOTJLVyIsImVuYyI6IkExOTJDQkMtSFMzODQiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0",
            recipients: [
              {
                header: {
                  kid: "did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1",
                  epk: {
                    kty: "EC",
                    crv: "P-256",
                    x: "GUtJcqQIoICjgEt6r1HrjOI7ear6iz3iuE0-Jsyzbkg",
                    y: "sWzrTpsZY_km6sy7hm-3QarYI7fTzZ3rVIGBO3VxxQI",
                  },
                },
                encrypted_key: "kReOkR4HqFwt7jMm52sEPToZma35HSY8Xt6ZzFWuk4L8XqnpMG5dLvvDtcL5Q6p-1Hm65v9tGAc",
              },
            ],
            iv: "VixoPcu2FikZneVLvwMzBw",
            ciphertext: "SCHS3In7w0fsjtG8aby2Tf5pDu08whXSYIFGtCPRcmQ",
            tag: "oYkPpxj1KHodN3Y5MmQy8JkRgc7iVJik",
          };

          const json = await decryptJson(jwe, jwks[0].private);

          expect(json).toEqual(payload);
        });

        it("and enc=`A256CBC-HS512`", async () => {
          const jwe = {
            protected:
              "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0",
            recipients: [
              {
                header: {
                  kid: "did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1",
                  epk: {
                    kty: "EC",
                    crv: "P-256",
                    x: "SgcD79Vnnaq4J2UTHXV6NFLo487O7x6Y5fuTQVOrx5Y",
                    y: "IXCWiytch8uhahH8zMFV6ZrrgIcrjbbZTzR6yTXRPWE",
                  },
                },
                encrypted_key:
                  "nls1fK_x25dCe4DBb_pqja2J_fCVvwFqXp3IAeRWuxzpulGvPcD3Tv1OJmovCZtUkSUPRI5PXBDekYDaV9ToZcAkXd49x-HH",
              },
            ],
            iv: "-Hir7AlhSBmZta-umWi-8g",
            ciphertext: "SI_4RoivOML5IGz5KuBkkJ1aqmLZK-_yN5w1r-cvaTI",
            tag: "PDizmeM8K-nrMHYRWhQcOk01CtsB4w3MkoZSwOjjWas",
          };

          const json = await decryptJson(jwe, jwks[0].private);

          expect(json).toEqual(payload);
        });
      });
    });
  });
});
