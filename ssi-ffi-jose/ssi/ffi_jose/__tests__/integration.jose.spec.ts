import {
  generateKeyPair,
  GeneralEncrypt,
  generalDecrypt
} from "../node_modules/jose";

const encoder = new TextEncoder()

describe("jose node package integration", () => {

  it('encrypt & decrypt', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES512')
    const JWT = {  message: "MESSAGE" }
    const serialisedJWT = JSON.stringify(JWT)
    const alg = 'ECDH-ES+A256KW', enc = 'A256GCM'

    const jwe = await new GeneralEncrypt(encoder.encode(serialisedJWT))
      .setProtectedHeader({ alg, enc, typ: 'application/didcomm-encrypted+json' })

    jwe.addRecipient(publicKey)

    const JWE = await jwe.encrypt()

    expect(Object.keys(JWE).sort()).toEqual(['ciphertext', "iv", "protected", "recipients", "tag"])
    expect(JWE.recipients.length).toBe(1)
    expect(Object.keys(JWE.recipients[0])).toEqual(['encrypted_key'])

    const jwt = await generalDecrypt(JWE, privateKey)

    expect(Object.keys(jwt).sort()).toEqual(['plaintext', 'protectedHeader'])
    expect(JSON.parse(Buffer.from(jwt.plaintext).toString())).toEqual(JWT)
  })

});
