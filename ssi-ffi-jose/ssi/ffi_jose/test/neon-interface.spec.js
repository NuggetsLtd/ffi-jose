const jose = require('../native')

const base64RegExp = /^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?$/i

const NamedCurve = {
  // EC curves
  P256: 0,
  P384: 1,
  P521: 2,
  Secp256k1: 3,
  // ED curves
  Ed25519: 4,
  Ed448: 5,
  // ECX curves
  X25519: 6,
  X448: 7
}

const ContentEncryption = {
  A128GCM: 0,
  A192GCM: 1,
  A256GCM: 2,
  'A128CBC-HS256': 3,
  'A192CBC-HS384': 4,
  'A256CBC-HS512': 5
}

const KeyEncryption = {
  // Direct encryption
  'dir': 0,
  // Diffie-Hellman
  'ECDH-ES': 1,
  'ECDH-ES+A128KW': 2,
  'ECDH-ES+A192KW': 3,
  'ECDH-ES+A256KW': 4,
  // RSAES
  'RSA1_5': 5,
  'RSA-OAEP': 6,
  'RSA-OAEP-256': 7,
  'RSA-OAEP-384': 8,
  'RSA-OAEP-512': 9,
  // PBES2
  'PBES2-HS256+A128KW': 10,
  'PBES2-HS384+A192KW': 11,
  'PBES2-HS512+A256KW': 12,
  // AES Key Wrap
  'A128KW': 13,
  'A192KW': 14,
  'A256KW': 15,
  // AES GCM Key wrap
  'A128GCMKW': 16,
  'A192GCMKW': 17,
  'A256GCMKW': 18
}

const base64ToArrayBuffer = (value) =>
  Uint8Array.from(Buffer.from(value, 'base64')).buffer

describe('NEON NodeJS Interface:', () => {

  it('should export the expected items', () => {
    expect(Object.keys(jose).sort()).toEqual([
      'decrypt',
      'decrypt_json',
      'encrypt',
      'general_encrypt_json',
      'generate_key_pair',
      'generate_key_pair_jwk'
    ])
  })

  it('should export foreign function interface functions', () => {
    expect(typeof jose.decrypt).toBe('function')
    expect(typeof jose.decrypt_json).toBe('function')
    expect(typeof jose.encrypt).toBe('function')
    expect(typeof jose.general_encrypt_json).toBe('function')
    expect(typeof jose.generate_key_pair).toBe('function')
    expect(typeof jose.generate_key_pair_jwk).toBe('function')
  })

  describe('Functions', () => {

    describe('generate_key_pair_jwk()', () => {

      it('where "namedCurve" is "P-256"', () => {
        const namedCurve = NamedCurve.P256
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('EC')
        expect(jwk.crv).toBe('P-256')
        expect(Buffer.from(jwk.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.y, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "P-384"', () => {
        const namedCurve = NamedCurve.P384
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('EC')
        expect(jwk.crv).toBe('P-384')
        expect(Buffer.from(jwk.d, 'base64').length).toBe(48)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(48)
        expect(Buffer.from(jwk.y, 'base64').length).toBe(48)
      })

      it('where "namedCurve" is "P-521"', () => {
        const namedCurve = NamedCurve.P521
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('EC')
        expect(jwk.crv).toBe('P-521')
        expect(Buffer.from(jwk.d, 'base64').length).toBe(66)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(66)
        expect(Buffer.from(jwk.y, 'base64').length).toBe(66)
      })

      it('where "namedCurve" is "secp256k1"', () => {
        const namedCurve = NamedCurve.Secp256k1
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('EC')
        expect(jwk.crv).toBe('secp256k1')
        expect(Buffer.from(jwk.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.y, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "Ed25519"', () => {
        const namedCurve = NamedCurve.Ed25519
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('OKP')
        expect(jwk.crv).toBe('Ed25519')
        expect(Buffer.from(jwk.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "Ed448"', () => {
        const namedCurve = NamedCurve.Ed448
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('OKP')
        expect(jwk.crv).toBe('Ed448')
        expect(Buffer.from(jwk.d, 'base64').length).toBe(57)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(57)
      })

      it('where "namedCurve" is "X25519"', () => {
        const namedCurve = NamedCurve.X25519
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('OKP')
        expect(jwk.crv).toBe('X25519')
        expect(Buffer.from(jwk.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "X448"', () => {
        const namedCurve = NamedCurve.X448
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('OKP')
        expect(jwk.crv).toBe('X448')
        expect(Buffer.from(jwk.d, 'base64').length).toBe(56)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(56)
      })

    })

    describe('generate_key_pair()', () => {

      it('should return expected object structure', () => {
        const namedCurve = NamedCurve.P256
        const keyPair = JSON.parse(jose.generate_key_pair({ namedCurve }))

        expect(keyPair).toEqual(expect.objectContaining({
          der_private_key: expect.stringMatching(base64RegExp),
          der_public_key: expect.stringMatching(base64RegExp),
          jwk_key_pair: expect.objectContaining({
            kty: expect.any(String),
            crv: expect.any(String),
            d: expect.any(String),
            x: expect.any(String),
            y: expect.any(String)
          }),
          jwk_private_key: expect.objectContaining({
            kty: expect.any(String),
            crv: expect.any(String),
            d: expect.any(String)
          }),
          jwk_public_key: expect.objectContaining({
            kty: expect.any(String),
            crv: expect.any(String),
            x: expect.any(String),
            y: expect.any(String)
          }),
          pem_private_key: expect.stringMatching(base64RegExp),
          pem_public_key: expect.stringMatching(base64RegExp)
        }))
      })

      it('where "namedCurve" is "P-256"', () => {
        const namedCurve = NamedCurve.P256
        const { jwk_key_pair } = JSON.parse(jose.generate_key_pair({ namedCurve }))

        expect(jwk_key_pair.kty).toBe('EC')
        expect(jwk_key_pair.crv).toBe('P-256')
        expect(Buffer.from(jwk_key_pair.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk_key_pair.x, 'base64').length).toBe(32)
        expect(Buffer.from(jwk_key_pair.y, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "P-384"', () => {
        const namedCurve = NamedCurve.P384
        const { jwk_key_pair } = JSON.parse(jose.generate_key_pair({ namedCurve }))

        expect(jwk_key_pair.kty).toBe('EC')
        expect(jwk_key_pair.crv).toBe('P-384')
        expect(Buffer.from(jwk_key_pair.d, 'base64').length).toBe(48)
        expect(Buffer.from(jwk_key_pair.x, 'base64').length).toBe(48)
        expect(Buffer.from(jwk_key_pair.y, 'base64').length).toBe(48)
      })

      it('where "namedCurve" is "P-521"', () => {
        const namedCurve = NamedCurve.P521
        const { jwk_key_pair } = JSON.parse(jose.generate_key_pair({ namedCurve }))

        expect(jwk_key_pair.kty).toBe('EC')
        expect(jwk_key_pair.crv).toBe('P-521')
        expect(Buffer.from(jwk_key_pair.d, 'base64').length).toBe(66)
        expect(Buffer.from(jwk_key_pair.x, 'base64').length).toBe(66)
        expect(Buffer.from(jwk_key_pair.y, 'base64').length).toBe(66)
      })

      it('where "namedCurve" is "secp256k1"', () => {
        const namedCurve = NamedCurve.Secp256k1
        const { jwk_key_pair } = JSON.parse(jose.generate_key_pair({ namedCurve }))

        expect(jwk_key_pair.kty).toBe('EC')
        expect(jwk_key_pair.crv).toBe('secp256k1')
        expect(Buffer.from(jwk_key_pair.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk_key_pair.x, 'base64').length).toBe(32)
        expect(Buffer.from(jwk_key_pair.y, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "Ed25519"', () => {
        const namedCurve = NamedCurve.Ed25519
        const { jwk_key_pair } = JSON.parse(jose.generate_key_pair({ namedCurve }))

        expect(jwk_key_pair.kty).toBe('OKP')
        expect(jwk_key_pair.crv).toBe('Ed25519')
        expect(Buffer.from(jwk_key_pair.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk_key_pair.x, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "Ed448"', () => {
        const namedCurve = NamedCurve.Ed448
        const { jwk_key_pair } = JSON.parse(jose.generate_key_pair({ namedCurve }))

        expect(jwk_key_pair.kty).toBe('OKP')
        expect(jwk_key_pair.crv).toBe('Ed448')
        expect(Buffer.from(jwk_key_pair.d, 'base64').length).toBe(57)
        expect(Buffer.from(jwk_key_pair.x, 'base64').length).toBe(57)
      })

      it('where "namedCurve" is "X25519"', () => {
        const namedCurve = NamedCurve.X25519
        const { jwk_key_pair } = JSON.parse(jose.generate_key_pair({ namedCurve }))

        expect(jwk_key_pair.kty).toBe('OKP')
        expect(jwk_key_pair.crv).toBe('X25519')
        expect(Buffer.from(jwk_key_pair.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk_key_pair.x, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "X448"', () => {
        const namedCurve = NamedCurve.X448
        const { jwk_key_pair } = JSON.parse(jose.generate_key_pair({ namedCurve }))

        expect(jwk_key_pair.kty).toBe('OKP')
        expect(jwk_key_pair.crv).toBe('X448')
        expect(Buffer.from(jwk_key_pair.d, 'base64').length).toBe(56)
        expect(Buffer.from(jwk_key_pair.x, 'base64').length).toBe(56)
      })

    })

    describe('encrypt()', () => {
      const plaintext = base64ToArrayBuffer('UExBSU5URVhU')
      const aad = base64ToArrayBuffer('')

      describe('should encrypt correctly', () => {

        describe('where enc type is `GCM`', () => {
          const iv = Uint8Array.from(Buffer.from('eae7e2df51f0dc34c39183e8', 'hex')).buffer

          it('and enc=`A128GCM`', () => {
            const enc = ContentEncryption.A128GCM
            const key = Uint8Array.from(Buffer.from('b8aae648b9c7819e24f2b2c684efcef1', 'hex')).buffer

            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            expect(encrypted.ciphertext).toBe('myTSDh9Ltc1H')
            expect(encrypted.tag).toBe('aFebG2ev+cSucVzhgvnePw==')
          })

          it('and enc=`A192GCM`', () => {
            const enc = ContentEncryption.A192GCM
            const key = Uint8Array.from(Buffer.from('5d9e61b7536901f89ffe729b2e94917987d6aee671d7c1a7', 'hex')).buffer

            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            expect(encrypted.ciphertext).toBe('2VNmCSsjuns3')
            expect(encrypted.tag).toBe('fXf8J7mEhy3Eqxz1mnkwQA==')
          })

          it('and enc=`A256GCM`', () => {
            const enc = ContentEncryption.A256GCM
            const key = Uint8Array.from(Buffer.from('4f0579c975d04ae004c9a2fd6620ad10bf763159a0e6894c6c0818acc5c24854', 'hex')).buffer

            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            expect(encrypted.ciphertext).toBe('PR+o7dKQmWjY')
            expect(encrypted.tag).toBe('no6xZQhgTVtaG6GHuEjlRA==')
          })

        })

        describe('where enc type is `CBC`', () => {
          const iv = Uint8Array.from(Buffer.from('5ee779854f0e37e83f39441c86cebe90', 'hex')).buffer

          it('and enc=`A128CBC-HS256`', () => {
            const enc = ContentEncryption['A128CBC-HS256']
            const key = Uint8Array.from(Buffer.from('4f0579c975d04ae004c9a2fd6620ad10bf763159a0e6894c6c0818acc5c24854', 'hex')).buffer

            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            expect(encrypted.ciphertext).toBe('tr3878VMma/zPqRGu7rI1g==')
            expect(encrypted.tag).toBe('8BR2fw5Twj9f7/5S7BEEhw==')
          })

          it('and enc=`A192CBC-HS384`', () => {
            const enc = ContentEncryption['A192CBC-HS384']
            const key = Uint8Array.from(Buffer.from('1d859097f5c1c883bdb5947466a85c2182373e94087b6f9895bc082e476da8d29817b0966db6e8003706d4d4daaf5a86', 'hex')).buffer

            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            expect(encrypted.ciphertext).toBe('1qIUH/OEDpztOf0sk1iK5g==')
            expect(encrypted.tag).toBe('vylJiL27sZ8Sq63KXNfslNb/aqRhRSyk')
          })

          it('and enc=`A256CBC-HS512`', () => {
            const enc = ContentEncryption['A256CBC-HS512']
            const key = Uint8Array.from(Buffer.from('cbd2a7b6f333ace24f3b7dad6579b40f97546ea59b3cf2325100ab78e46126d0521e515aa33e2af140308988d06ea15f96a0d3c794b311a755dca5ace7fa1e94', 'hex')).buffer

            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            expect(encrypted.ciphertext).toBe('4CN6Qy2JV/+MeALSoHcKDg==')
            expect(encrypted.tag).toBe('ZerEUmGJgIblArz+GrdTmP0BNzk2fgqm71OgS6GzzJs=')
          })

        })

      })

    })

    describe('decrypt()', () => {
      const plaintextb64 = 'UExBSU5URVhU'
      const plaintext = base64ToArrayBuffer(plaintextb64)
      const aad = base64ToArrayBuffer('')

      describe('should decrypt correctly', () => {

        describe('where enc type is `GCM`', () => {
          const iv = Uint8Array.from(Buffer.from('eae7e2df51f0dc34c39183e8', 'hex')).buffer

          it('and enc=`A128GCM`', () => {
            const enc = ContentEncryption.A128GCM
            const key = Uint8Array.from(Buffer.from('b8aae648b9c7819e24f2b2c684efcef1', 'hex')).buffer
            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            const message = jose.decrypt(enc, key, base64ToArrayBuffer(encrypted.ciphertext), iv, base64ToArrayBuffer(encrypted.tag), aad)

            expect(message).toBe(plaintextb64)
          })

          it('and enc=`A192GCM`', () => {
            const enc = ContentEncryption.A192GCM
            const key = Uint8Array.from(Buffer.from('5d9e61b7536901f89ffe729b2e94917987d6aee671d7c1a7', 'hex')).buffer
            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            const message = jose.decrypt(enc, key, base64ToArrayBuffer(encrypted.ciphertext), iv, base64ToArrayBuffer(encrypted.tag), aad)

            expect(message).toBe(plaintextb64)
          })

          it('and enc=`A256GCM`', () => {
            const enc = ContentEncryption.A256GCM
            const key = Uint8Array.from(Buffer.from('4f0579c975d04ae004c9a2fd6620ad10bf763159a0e6894c6c0818acc5c24854', 'hex')).buffer
            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            const message = jose.decrypt(enc, key, base64ToArrayBuffer(encrypted.ciphertext), iv, base64ToArrayBuffer(encrypted.tag), aad)

            expect(message).toBe(plaintextb64)
          })

        })

        describe('where enc type is `CBC`', () => {
          const iv = Uint8Array.from(Buffer.from('5ee779854f0e37e83f39441c86cebe90', 'hex')).buffer

          it('and enc=`A128CBC-HS256`', () => {
            const enc = ContentEncryption['A128CBC-HS256']
            const key = Uint8Array.from(Buffer.from('4f0579c975d04ae004c9a2fd6620ad10bf763159a0e6894c6c0818acc5c24854', 'hex')).buffer
            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            const message = jose.decrypt(enc, key, base64ToArrayBuffer(encrypted.ciphertext), iv, base64ToArrayBuffer(encrypted.tag), aad)

            expect(message).toBe(plaintextb64)
          })

          it('and enc=`A192CBC-HS384`', () => {
            const enc = ContentEncryption['A192CBC-HS384']
            const key = Uint8Array.from(Buffer.from('1d859097f5c1c883bdb5947466a85c2182373e94087b6f9895bc082e476da8d29817b0966db6e8003706d4d4daaf5a86', 'hex')).buffer
            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            const message = jose.decrypt(enc, key, base64ToArrayBuffer(encrypted.ciphertext), iv, base64ToArrayBuffer(encrypted.tag), aad)

            expect(message).toBe(plaintextb64)
          })

          it('and enc=`A256CBC-HS512`', () => {
            const enc = ContentEncryption['A256CBC-HS512']
            const key = Uint8Array.from(Buffer.from('cbd2a7b6f333ace24f3b7dad6579b40f97546ea59b3cf2325100ab78e46126d0521e515aa33e2af140308988d06ea15f96a0d3c794b311a755dca5ace7fa1e94', 'hex')).buffer
            const encrypted = jose.encrypt(enc, key, iv, plaintext, aad)

            const message = jose.decrypt(enc, key, base64ToArrayBuffer(encrypted.ciphertext), iv, base64ToArrayBuffer(encrypted.tag), aad)

            expect(message).toBe(plaintextb64)
          })

        })

      })

    })

    describe('general_encrypt_jwt', () => {

      describe('should correctly encrypt payload', () => {
        const alg = KeyEncryption['ECDH-ES+A128KW']
        const enc = ContentEncryption.A128GCM
        const jwt = { hello: 'there' }
        const payload = JSON.stringify(jwt)
        const jwks = [
          {
            public: {
              kid: 'did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1',
              kty: 'EC',
              crv: 'P-256',
              x: 'A4NKTvWeEv3b-sJnlmwrATDklidT_qo3jTYRV2shaAc',
              y: '_06GxhBcbxJzOCTz4F0kq_mETgGti33WkFpMKZHc-SY'
            },
            private: {
              kid: 'did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1',
              kty: 'EC',
              crv: 'P-256',
              d: 'qjx4ib5Ea94YnyypBBPnvtGUuoRgGtF_0BtPuOSMJPc'
            }
          },
          {
            public: {
              kid: 'did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p256-1',
              kty: 'EC',
              crv: 'P-256',
              x: 'YQbhZhp4ORKjwMqQIGFbIVSyYaaBuJbym_UWEWJPgbM',
              y: 'hxHEiOwPXUt1Nv_3MO5oRkUoMtYFaWIzW0iiZMNTnFE'
            },
            private: {
              kid: 'did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p256-1',
              kty: 'EC',
              crv: 'P-256',
              d: 'pndx4RjZSMpYjkokcn5xcIfmhZV19-jr_0n4l1kcphI'
            }
          }
        ]

        it('for single recipient', async () => {
          const recipients = JSON.stringify([ jwks[0].public ])

          // encrypt message
          const jwe = jose.general_encrypt_json(alg, enc, payload, recipients)

          // decrypt message
          const decryptedMsg = JSON.parse(jose.decrypt_json(jwe, JSON.stringify(jwks[0].private)))
          expect(decryptedMsg).toEqual(jwt)
        })

        it('for multiple recipients', async () => {
          const recipients = JSON.stringify([ jwks[0].public, jwks[1].public ])

          // encrypt message with multiple recipients
          const jwe = jose.general_encrypt_json(alg, enc, payload, recipients)

          // decrypt message for first recipient
          const decryptedMsg1 = JSON.parse(jose.decrypt_json(jwe, JSON.stringify(jwks[0].private)))
          expect(decryptedMsg1).toEqual(jwt)

          // decrypt message for second recipient
          const decryptedMsg2 = JSON.parse(jose.decrypt_json(jwe, JSON.stringify(jwks[1].private)))
          expect(decryptedMsg2).toEqual(jwt)
        })

      })

    })

  })

})
