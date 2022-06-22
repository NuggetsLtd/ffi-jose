const jose = require('../native')

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
    X448: 7,
}

describe('NEON NodeJS Interface:', () => {

  it('should export the expected items', () => {
    expect(Object.keys(jose)).toEqual([
      'generate_key_pair_jwk'
    ])
  })

  it('should export foreign function interface functions', () => {
    expect(typeof jose.generate_key_pair_jwk).toBe('function')
  })

  describe('Functions', () => {

    describe('generate_key_pair_jwk()', () => {

      it('where "namedCurve" is "P-256"', async () => {
        const namedCurve = NamedCurve.P256
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('EC')
        expect(jwk.crv).toBe("P-256")
        expect(Buffer.from(jwk.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.y, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "P-384"', async () => {
        const namedCurve = NamedCurve.P384
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('EC')
        expect(jwk.crv).toBe("P-384")
        expect(Buffer.from(jwk.d, 'base64').length).toBe(48)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(48)
        expect(Buffer.from(jwk.y, 'base64').length).toBe(48)
      })

      it('where "namedCurve" is "P-521"', async () => {
        const namedCurve = NamedCurve.P521
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('EC')
        expect(jwk.crv).toBe("P-521")
        expect(Buffer.from(jwk.d, 'base64').length).toBe(66)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(66)
        expect(Buffer.from(jwk.y, 'base64').length).toBe(66)
      })

      it('where "namedCurve" is "secp256k1"', async () => {
        const namedCurve = NamedCurve.Secp256k1
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('EC')
        expect(jwk.crv).toBe("secp256k1")
        expect(Buffer.from(jwk.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.y, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "Ed25519"', async () => {
        const namedCurve = NamedCurve.Ed25519
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('OKP')
        expect(jwk.crv).toBe("Ed25519")
        expect(Buffer.from(jwk.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "Ed448"', async () => {
        const namedCurve = NamedCurve.Ed448
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('OKP')
        expect(jwk.crv).toBe("Ed448")
        expect(Buffer.from(jwk.d, 'base64').length).toBe(57)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(57)
      })

      it('where "namedCurve" is "X25519"', async () => {
        const namedCurve = NamedCurve.X25519
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('OKP')
        expect(jwk.crv).toBe("X25519")
        expect(Buffer.from(jwk.d, 'base64').length).toBe(32)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(32)
      })

      it('where "namedCurve" is "X448"', async () => {
        const namedCurve = NamedCurve.X448
        const jwk = JSON.parse(jose.generate_key_pair_jwk({ namedCurve }))

        expect(jwk.kty).toBe('OKP')
        expect(jwk.crv).toBe("X448")
        expect(Buffer.from(jwk.d, 'base64').length).toBe(56)
        expect(Buffer.from(jwk.x, 'base64').length).toBe(56)
      })

    })

  })

})
