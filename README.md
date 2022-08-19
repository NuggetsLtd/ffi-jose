[![Nuggets](./docs/assets/nuggets-logo.svg)](https://github.com/NuggetsLtd)

# Node JOSE FFI (Foreign Function Interface)

![npm-version](https://badgen.net/npm/v/@nuggetslife/ffi-jose)
![npm-unstable-version](https://badgen.net/npm/v/@nuggetslife/ffi-jose/unstable)
![Master](https://github.com/NuggetsLtd/ffi-jose/workflows/push-master/badge.svg)
![Release](https://github.com/NuggetsLtd/ffi-jose/workflows/push-release/badge.svg)
![codecov](https://codecov.io/gh/NuggetsLtd/ffi-jose/branch/master/graph/badge.svg)

Implementation of standardised JOSE functions, for exposure in various JavaScript environments (i.e. NodeJS, React
Native).

## Getting started

To use this package within your project simply run:

**npm**

```
npm install @nuggetslife/ffi-jose
```

**yarn**

```
yarn add @nuggetslife/ffi-jose
```

## Usage

<!-- See the [sample](./sample) directory for a runnable demo. -->

**Key generation:**

```typescript
import { generateJWK, generateKeyPair, NamedCurve } from "@nuggetslife/ffi-jose";

// Generate a new JWK
const jwk = await generateJWK({ namedCurve: NamedCurve.P256 });

// Generate a new key pair
const keyPair = await generateKeyPair("ec", { namedCurve: NamedCurve.P256 });
```

**Encrypt / Decrypt:**

```javascript
import { encrypt, decrypt } from "@nuggetslife/ffi-jose";

const enc = "A128GCM";
const plaintext = Uint8Array.from(Buffer.from("PLAINTEXT"));
const cek = Uint8Array.from(Buffer.from("b8aae648b9c7819e24f2b2c684efcef1", "hex"));
const iv = Uint8Array.from(Buffer.from("eae7e2df51f0dc34c39183e8", "hex"));
const aad = Uint8Array.from(Buffer.from("", "base64"));

// encrypt some data
const encrypted = await encrypt(enc, plaintext, cek, iv, aad);

// decrypt data
const decrypted = await decrypt(
  enc,
  cek,
  encrypted.ciphertext,
  iv,
  encrypted.tag || Uint8Array.from(Buffer.from("")),
  aad
);
```

**JOSE General encrypt / decrypt:**

```javascript
import { generalEncryptJson, decryptJson, KeyEncryption, ContentEncryption } from "@nuggetslife/ffi-jose";

const alg = KeyEncryption.EcdhEsA128kw;
const enc = ContentEncryption.A128gcm;
const payload = {
  hello: "there",
};
const recipientJwkPublic = {
  kid: "did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1",
  kty: "EC",
  crv: "P-256",
  x: "A4NKTvWeEv3b-sJnlmwrATDklidT_qo3jTYRV2shaAc",
  y: "_06GxhBcbxJzOCTz4F0kq_mETgGti33WkFpMKZHc-SY",
};
const recipientJwkPrivate = {
  kid: "did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1",
  kty: "EC",
  crv: "P-256",
  d: "qjx4ib5Ea94YnyypBBPnvtGUuoRgGtF_0BtPuOSMJPc",
};
const recipients = [recipientJwkPublic];

// encrypt some data
const jwe = await generalEncryptJson(alg, enc, payload, recipients);

// decrypt data
const json = await decryptJson(jwe, recipientJwkPrivate);
```

## Getting started as a contributor

The following describes how to get started as a contributor to this project

### Prerequisites

The following is a list of dependencies you must install to build and contribute to this project

- [Yarn](https://yarnpkg.com/)
- [Rust](https://www.rust-lang.org/)

For more details see our [contribution guidelines](./docs/CONTRIBUTING.md)

#### Install

To install the package dependencies run:

```
yarn install --frozen-lockfile
```

#### Build

To build the project run:

```
yarn build
```

#### Test

To run the test in the project run:

```
yarn test
```

#### Benchmark

To benchmark the implementation locally run:

```
yarn benchmark
```

## Dependencies

This library uses the [josekit](https://crates.io/crates/josekit) rust crate for the implementation of JOSE, which is
then wrapped and exposed in javascript/typescript using [neon-bindings](https://github.com/neon-bindings/neon).

## Security Policy

Please see our [security policy](./SECURITY.md) for additional details about responsible disclosure of security related
issues.

---

<p align="center"><a href="https://nuggets.life" target="_blank"><img height="40px" src ="./docs/assets/nuggets-logo.svg"></a></p><p align="center">Copyright © Nuggets Limited. <a href="./LICENSE">Some rights reserved.</a></p>
