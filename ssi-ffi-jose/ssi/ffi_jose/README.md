# Rust JOSE Foreign Function Interface (FFI)

A package to wrap a Rust JOSE Crate for use in Node, Android & iOS.

This package is required, as some of the Node `crypto` module functionality is not available in React Native. Specifically, `generateKeyPair`. There are no JS shims for this, seemigly as they wouldn't be performant enough to be useable.

This is actually an opportunity, as using Rust should give us significant performance benefits over functionality written in JS on mobile devices.

Creating an FFI means that we can have a common interface for this functionality in Node, Android and iOS, simplifying the overall architecture.

Functionality provided by this package is as follows:

- Key Pair Generation
- JWT Signing & Verification
- JWT Encryption & Decryption

## Javascript
Javascript interface for JOSE functionality in Rust.

### Install packages
```sh
yarn
```

### Build Neon Bindings
Build the interface between Rust & Javascript:
```sh
yarn build:neon
```

### Test Neon Bindings
Test the interface between Rust & Javascript:
```sh
yarn test:neon
```

### Build Typescript
Build typescript code for javascript `@nuggetslife/ffi-jose` package:
```sh
yarn build:ts
```

### Test Typescript
Test typescript code:
```sh
yarn test:ts
```

## C
C interface for JOSE functionality in Rust.

### Build C Bindings
Build the interface between Rust & C:
```sh
yarn build:c
```

### Test C Bindings
Test the interface between Rust & C:
```sh
yarn test:c
```
