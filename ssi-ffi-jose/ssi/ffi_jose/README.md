# Rust JOSE Foreign Function Interface (FFI)

A package to wrap a Rust JOSE Crate for use in Node, Android & iOS.

This package is required, as some of the Node `crypto` module functionality is not available in React Native. Specifically, `generateKeyPair`. There are no JS shims for this, seemigly as they wouldn't be performant enough to be useable.

This is actually an opportunity, as using Rust should give us significant performance benefits over functionality written in JS on mobile devices.

Creating an FFI means that we can have a common interface for this functionality in Node, Android and iOS, simplifying the overall architecture.

Functionality provided by this package is as follows:

- Key Pair Generation
- JWT Signing & Verification
- JWT Encryption & Decryption

## Pre-Requisites
For building this package, you will need to have OpenSSL installed. This is due to the Rust `josekit` package requiring this dependency.

### Mac
Check if OpenSSL is installed:
```sh
brew info openssl
```

Upgrade crates to the latest (if already installed):
```sh
brew upgrade
```

Install OpenSSL (if not installed):
```sh
brew install openssl@1.1
```

#### ZSH Users
Export `OPENSSL_DIR` env var for `openssl` location:
```sh
echo 'export OPENSSL_DIR="/usr/local/opt/openssl@1.1"' >> ~/.zshrc
```

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

## C / iOS
C / iOS interface for JOSE functionality in Rust.

### Build iOS packages
Build iOS-specific packages:
```sh
yarn build:ios
```

### Test C Bindings
Test the interface between Rust & C:
```sh
yarn test:c
```

## Java / Android
Java / Android interface for JOSE functionality in Rust.

### Build Android packages
Build Android-specific packages:
```sh
yarn build:android
```
