import { describe, it, expect } from "vitest";
import { encrypt, decrypt } from "../src";

const base64ToArrayBuffer = (value: string) => Uint8Array.from(Buffer.from(value, "base64"));

describe("jose", () => {
  describe("decrypt", () => {
    const plaintextb64 = "UExBSU5URVhU";
    const plaintext = base64ToArrayBuffer(plaintextb64);
    const aad = base64ToArrayBuffer("");

    describe("should decrypt to plaintext correctly", () => {
      describe("where enc type is `GCM`", () => {
        const iv = Uint8Array.from(Buffer.from("eae7e2df51f0dc34c39183e8", "hex"));

        it("and `enc` = 'A128GCM'", async () => {
          const enc = "A128GCM";
          const cek = Uint8Array.from(Buffer.from("b8aae648b9c7819e24f2b2c684efcef1", "hex"));
          const encrypted = await encrypt(enc, plaintext, cek, iv, aad);

          const decrypted = await decrypt(
            enc,
            cek,
            encrypted.ciphertext,
            iv,
            encrypted.tag || Uint8Array.from(Buffer.from("")),
            aad
          );

          expect(Buffer.from(decrypted).toString("base64")).toBe(plaintextb64);
        });

        it("and `enc` = 'A192GCM'", async () => {
          const enc = "A192GCM";
          const cek = Uint8Array.from(Buffer.from("5d9e61b7536901f89ffe729b2e94917987d6aee671d7c1a7", "hex"));
          const encrypted = await encrypt(enc, plaintext, cek, iv, aad);

          const decrypted = await decrypt(
            enc,
            cek,
            encrypted.ciphertext,
            iv,
            encrypted.tag || Uint8Array.from(Buffer.from("")),
            aad
          );

          expect(Buffer.from(decrypted).toString("base64")).toBe(plaintextb64);
        });

        it("and `enc` = 'A256GCM'", async () => {
          const enc = "A256GCM";
          const cek = Uint8Array.from(
            Buffer.from("4f0579c975d04ae004c9a2fd6620ad10bf763159a0e6894c6c0818acc5c24854", "hex")
          );
          const encrypted = await encrypt(enc, plaintext, cek, iv, aad);

          const decrypted = await decrypt(
            enc,
            cek,
            encrypted.ciphertext,
            iv,
            encrypted.tag || Uint8Array.from(Buffer.from("")),
            aad
          );

          expect(Buffer.from(decrypted).toString("base64")).toBe(plaintextb64);
        });
      });

      describe("where enc type is `CBC`", () => {
        const iv = Uint8Array.from(Buffer.from("5ee779854f0e37e83f39441c86cebe90", "hex"));

        it("and enc=`A128CBC-HS256`", async () => {
          const enc = "A128CBC-HS256";
          const cek = Uint8Array.from(
            Buffer.from("4f0579c975d04ae004c9a2fd6620ad10bf763159a0e6894c6c0818acc5c24854", "hex")
          );
          const encrypted = await encrypt(enc, plaintext, cek, iv, aad);

          const decrypted = await decrypt(
            enc,
            cek,
            encrypted.ciphertext,
            iv,
            encrypted.tag || Uint8Array.from(Buffer.from("")),
            aad
          );

          expect(Buffer.from(decrypted).toString("base64")).toBe(plaintextb64);
        });

        it("and enc=`A192CBC-HS384`", async () => {
          const enc = "A192CBC-HS384";
          const cek = Uint8Array.from(
            Buffer.from(
              "1d859097f5c1c883bdb5947466a85c2182373e94087b6f9895bc082e476da8d29817b0966db6e8003706d4d4daaf5a86",
              "hex"
            )
          );
          const encrypted = await encrypt(enc, plaintext, cek, iv, aad);

          const decrypted = await decrypt(
            enc,
            cek,
            encrypted.ciphertext,
            iv,
            encrypted.tag || Uint8Array.from(Buffer.from("")),
            aad
          );

          expect(Buffer.from(decrypted).toString("base64")).toBe(plaintextb64);
        });

        it("and enc=`A256CBC-HS512`", async () => {
          const enc = "A256CBC-HS512";
          const cek = Uint8Array.from(
            Buffer.from(
              "cbd2a7b6f333ace24f3b7dad6579b40f97546ea59b3cf2325100ab78e46126d0521e515aa33e2af140308988d06ea15f96a0d3c794b311a755dca5ace7fa1e94",
              "hex"
            )
          );
          const encrypted = await encrypt(enc, plaintext, cek, iv, aad);

          const decrypted = await decrypt(
            enc,
            cek,
            encrypted.ciphertext,
            iv,
            encrypted.tag || Uint8Array.from(Buffer.from("")),
            aad
          );

          expect(Buffer.from(decrypted).toString("base64")).toBe(plaintextb64);
        });
      });
    });
  });
});
