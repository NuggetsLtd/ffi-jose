import {
  NamedCurve,
  generateKeyPair,
  JoseGenerateJwkRequest,
} from "../src";

describe("jose", () => {

  describe("generateKeyPair", () => {

    describe('should generate a valid Key Pair', () => {

      it("where `namedCurve` = 'P256'", async () => {
        const type = 'ec'
        const crv = 'P-256'
        const keyPair = await generateKeyPair(type, {
          namedCurve: crv
        })
  
        expect(keyPair).toBeInstanceOf(Object)
        expect(Object.keys(keyPair).sort()).toEqual([ 'privateKey', "publicKey", ])
        expect(keyPair.privateKey.type).toEqual("private")
        expect(keyPair.privateKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.privateKey.asymmetricKeyDetails).toEqual(crv)
        expect(keyPair.publicKey.type).toEqual("public")
        expect(keyPair.publicKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.publicKey.asymmetricKeyDetails).toEqual(crv)
      });

      it("where `namedCurve` = 'P384'", async () => {
        const type = 'ec'
        const crv = 'P-384'
        const keyPair = await generateKeyPair(type, {
          namedCurve: crv
        })
  
        expect(keyPair).toBeInstanceOf(Object)
        expect(Object.keys(keyPair).sort()).toEqual([ 'privateKey', "publicKey", ])
        expect(keyPair.privateKey.type).toEqual("private")
        expect(keyPair.privateKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.privateKey.asymmetricKeyDetails).toEqual(crv)
        expect(keyPair.publicKey.type).toEqual("public")
        expect(keyPair.publicKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.publicKey.asymmetricKeyDetails).toEqual(crv)
      });

      it("where `namedCurve` = 'P521'", async () => {
        const type = 'ec'
        const crv = 'P-521'
        const keyPair = await generateKeyPair(type, {
          namedCurve: crv
        })
  
        expect(keyPair).toBeInstanceOf(Object)
        expect(Object.keys(keyPair).sort()).toEqual([ 'privateKey', "publicKey", ])
        expect(keyPair.privateKey.type).toEqual("private")
        expect(keyPair.privateKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.privateKey.asymmetricKeyDetails).toEqual(crv)
        expect(keyPair.publicKey.type).toEqual("public")
        expect(keyPair.publicKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.publicKey.asymmetricKeyDetails).toEqual(crv)
      });

      it("where `namedCurve` = 'secp256k1'", async () => {
        const type = 'ec'
        const crv = 'secp256k1'
        const keyPair = await generateKeyPair(type, {
          namedCurve: crv
        })
  
        expect(keyPair).toBeInstanceOf(Object)
        expect(Object.keys(keyPair).sort()).toEqual([ 'privateKey', "publicKey", ])
        expect(keyPair.privateKey.type).toEqual("private")
        expect(keyPair.privateKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.privateKey.asymmetricKeyDetails).toEqual(crv)
        expect(keyPair.publicKey.type).toEqual("public")
        expect(keyPair.publicKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.publicKey.asymmetricKeyDetails).toEqual(crv)
      });

      it("where `namedCurve` = 'Ed25519'", async () => {
        const type = 'ed25519'
        const keyPair = await generateKeyPair(type)
  
        expect(keyPair).toBeInstanceOf(Object)
        expect(Object.keys(keyPair).sort()).toEqual([ 'privateKey', "publicKey", ])
        expect(keyPair.privateKey.type).toEqual("private")
        expect(keyPair.privateKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.privateKey.asymmetricKeyDetails).toEqual({})
        expect(keyPair.publicKey.type).toEqual("public")
        expect(keyPair.publicKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.publicKey.asymmetricKeyDetails).toEqual({})
      });

      it("where `namedCurve` = 'Ed448'", async () => {
        const type = 'ed448'
        const keyPair = await generateKeyPair(type)
  
        expect(keyPair).toBeInstanceOf(Object)
        expect(Object.keys(keyPair).sort()).toEqual([ 'privateKey', "publicKey", ])
        expect(keyPair.privateKey.type).toEqual("private")
        expect(keyPair.privateKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.privateKey.asymmetricKeyDetails).toEqual({})
        expect(keyPair.publicKey.type).toEqual("public")
        expect(keyPair.publicKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.publicKey.asymmetricKeyDetails).toEqual({})
      });

      it("where `namedCurve` = 'X25519'", async () => {
        const type = 'x25519'
        const keyPair = await generateKeyPair(type)
  
        expect(keyPair).toBeInstanceOf(Object)
        expect(Object.keys(keyPair).sort()).toEqual([ 'privateKey', "publicKey", ])
        expect(keyPair.privateKey.type).toEqual("private")
        expect(keyPair.privateKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.privateKey.asymmetricKeyDetails).toEqual({})
        expect(keyPair.publicKey.type).toEqual("public")
        expect(keyPair.publicKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.publicKey.asymmetricKeyDetails).toEqual({})
      });

      it("where `namedCurve` = 'X448'", async () => {
        const type = 'x448'
        const keyPair = await generateKeyPair(type)
  
        expect(keyPair).toBeInstanceOf(Object)
        expect(Object.keys(keyPair).sort()).toEqual([ 'privateKey', "publicKey", ])
        expect(keyPair.privateKey.type).toEqual("private")
        expect(keyPair.privateKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.privateKey.asymmetricKeyDetails).toEqual({})
        expect(keyPair.publicKey.type).toEqual("public")
        expect(keyPair.publicKey.asymmetricKeyType).toEqual(type)
        expect(keyPair.publicKey.asymmetricKeyDetails).toEqual({})
      });

    })

    describe('should error', () => {

      it("where unknown curve type used", async () => {
        await expect(() => generateKeyPair('UNKNOWN')).rejects.toThrow('Invalid or unsupported \"type\" Parameter value')
      });

    })

  });

});
