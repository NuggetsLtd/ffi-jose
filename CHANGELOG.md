## [2.0.12](https://github.com/NuggetsLtd/ffi-jose/compare/v2.0.11...v2.0.12) (2024-03-01)



## [2.0.11](https://github.com/NuggetsLtd/ffi-jose/compare/v2.0.10...v2.0.11) (2024-03-01)



## [2.0.10](https://github.com/NuggetsLtd/ffi-jose/compare/v2.0.9...v2.0.10) (2024-03-01)



## [2.0.9](https://github.com/NuggetsLtd/ffi-jose/compare/v2.0.8...v2.0.9) (2024-03-01)



## [2.0.8](https://github.com/NuggetsLtd/ffi-jose/compare/v2.0.7...v2.0.8) (2024-03-01)


### Reverts

* Revert ":fire:  Comment out code for OpenSSL 1.1" ([4220ec2](https://github.com/NuggetsLtd/ffi-jose/commit/4220ec2c952b05524905afb9f980dc6efc2219d2))
* Revert ":fire:  Remove publish check" ([4217bb7](https://github.com/NuggetsLtd/ffi-jose/commit/4217bb733bac6249fa0abe8c392351aba8a6b0e8))
* Revert "chore(release): publish" ([fba1d77](https://github.com/NuggetsLtd/ffi-jose/commit/fba1d77461dffb81ecf16e1e9dcf50349f062451))



## [2.0.6](https://github.com/NuggetsLtd/ffi-jose/compare/v2.0.5...v2.0.6) (2023-05-11)



## [2.0.5](https://github.com/NuggetsLtd/ffi-jose/compare/2.0.4...2.0.5) (2023-05-11)



## [2.0.4](https://github.com/NuggetsLtd/ffi-jose/compare/v2.0.3...v2.0.4) (2023-05-11)



## [2.0.3](https://github.com/NuggetsLtd/ffi-jose/compare/2.0.2...2.0.3) (2023-04-27)



## [2.0.2](https://github.com/NuggetsLtd/ffi-jose/compare/v2.0.1...v2.0.2) (2023-03-31)



## [2.0.1](https://github.com/NuggetsLtd/ffi-jose/compare/v1.7.2...v2.0.1) (2022-11-18)


### Features

* add  token type option ([4478178](https://github.com/NuggetsLtd/ffi-jose/commit/44781780a2f6c2d3fb333fd8f6aa580f2d546ea8))
* tests for C FFI 'JWT' token type option ([ba63b24](https://github.com/NuggetsLtd/ffi-jose/commit/ba63b240720c6a6742266d20f92c7c1b11b918a6))
* tests for Java 'JWT' token type option ([7dc5818](https://github.com/NuggetsLtd/ffi-jose/commit/7dc5818fa1ee21279d3013366560f9d8fd44428d))
* tests for Node FFI 'JWT' token type option ([3481ded](https://github.com/NuggetsLtd/ffi-jose/commit/3481deda18568f66a9383e70ea04b0d05ab02dab))
* update C FFI to add 'JWT' token type option ([d03f54f](https://github.com/NuggetsLtd/ffi-jose/commit/d03f54f654f5259768f6d65022a64d283e0c6632))
* update Java FFI to add 'JWT' token type option ([dfc1837](https://github.com/NuggetsLtd/ffi-jose/commit/dfc18376e9a3bde8e8351419a6a30f37d7340e68))
* update Node FFI to add 'JWT' token type option ([206971c](https://github.com/NuggetsLtd/ffi-jose/commit/206971c9ed03f5e22a1c32c4a862249024a0796c))
* update typescript FFI 'JWT' token type option ([a88eb91](https://github.com/NuggetsLtd/ffi-jose/commit/a88eb91c21b666b7375a7ebad6ffa66d11c13832))



## [1.7.2](https://github.com/NuggetsLtd/ffi-jose/compare/v1.7.1...v1.7.2) (2022-09-16)


### Bug Fixes

* create directory before copying dylib file ([ae27db9](https://github.com/NuggetsLtd/ffi-jose/commit/ae27db9f417c4bc1c7f7170826b9ed491726f30a))
* return json from verification functions ([e1121d1](https://github.com/NuggetsLtd/ffi-jose/commit/e1121d14170b86e8e6c2ca5df44143e0d6fb4c0a))
* set 'typ' to didcomm signed ([d7861eb](https://github.com/NuggetsLtd/ffi-jose/commit/d7861eb6adeae4c5a2391f803130f5e14c70084c))


### Features

* add 'Java_life_nuggets_rs_Jose_compact_1json_1verify' FFI function ([6f5d742](https://github.com/NuggetsLtd/ffi-jose/commit/6f5d742856b83e72dd2202e83a03b9dfc1c7a0fa))
* add 'Java_life_nuggets_rs_Jose_compact_1sign_1json' FFI function ([800630c](https://github.com/NuggetsLtd/ffi-jose/commit/800630c814669cfa87bcf2fdf9feb49f37fb112e))
* add 'Java_life_nuggets_rs_Jose_flattened_1sign_1json' FFI function ([6ad9bf6](https://github.com/NuggetsLtd/ffi-jose/commit/6ad9bf68ad7fbd934d8130de2371d62cc12fc52b))
* add 'Java_life_nuggets_rs_Jose_general_1sign_1json' FFI function ([3542373](https://github.com/NuggetsLtd/ffi-jose/commit/35423739191b28aeaee39265101991f58e39be3b))
* add 'Java_life_nuggets_rs_Jose_json_1verify' FFI function ([7e60416](https://github.com/NuggetsLtd/ffi-jose/commit/7e6041645dc30de1d47059f91f97baa26a377d93))
* add C 'ffi_jose_compact_json_verify' function ([2d8d3cd](https://github.com/NuggetsLtd/ffi-jose/commit/2d8d3cd27a85ec2e52268a0103c77cbb5cdd2853))
* add C 'ffi_jose_compact_sign_json' function ([4c27282](https://github.com/NuggetsLtd/ffi-jose/commit/4c27282054c2f0ab4611d49c69b3a7e9082d80a6))
* add C 'ffi_jose_general_sign_json' function ([a606ba6](https://github.com/NuggetsLtd/ffi-jose/commit/a606ba63b2484f996f2977207d2698e81823209c))
* add C 'rust_flattened_sign_json' function ([c62bc1c](https://github.com/NuggetsLtd/ffi-jose/commit/c62bc1c873e0d1ff3248f826db1cb03fa5a6bedd))
* add C 'rust_json_verify' function ([440cdbf](https://github.com/NuggetsLtd/ffi-jose/commit/440cdbf05fc1b14f23e2ee897b1b1ee379d45d2f))
* add signing methods to 'Jose' class ([dc99bf9](https://github.com/NuggetsLtd/ffi-jose/commit/dc99bf9843e0932ba933c8d6c13e2984f0fa8564))
* check for 'kid' values on JWKs ([3106fc7](https://github.com/NuggetsLtd/ffi-jose/commit/3106fc7e92b1133cc973951493955144ed3bac7a))



## [1.7.1](https://github.com/NuggetsLtd/ffi-jose/compare/v1.7.0...v1.7.1) (2022-09-09)


### Bug Fixes

* use correct header for respective signers ([b7b82d2](https://github.com/NuggetsLtd/ffi-jose/commit/b7b82d2b014f402b9b72c5c13a452301033f3d9d))



# [1.7.0](https://github.com/NuggetsLtd/ffi-jose/compare/v1.6.1...v1.7.0) (2022-09-09)


### Features

* update 'generalSignJson' to pass 'alg' on each 'jwk' ([1dc6c69](https://github.com/NuggetsLtd/ffi-jose/commit/1dc6c697e40c75e6fc1de1c761cae75a2678cb21))
* update neon FFI to use 'alg' from jwk for 'node_general_sign_json' ([087f164](https://github.com/NuggetsLtd/ffi-jose/commit/087f164fec0dbfd989c1d5a760724064d258c0cf))
* use 'alg' from jwk for 'rust_general_sign_json' ([fcbbd23](https://github.com/NuggetsLtd/ffi-jose/commit/fcbbd23298d711e52ac3dd7d22288c4aaed4598d))



## [1.6.1](https://github.com/NuggetsLtd/ffi-jose/compare/v1.6.0...v1.6.1) (2022-09-09)


### Features

* add error msg to verification failure ([42cdb31](https://github.com/NuggetsLtd/ffi-jose/commit/42cdb31a6fcc684a7e6683e373375a0bb451856b))



# [1.6.0](https://github.com/NuggetsLtd/ffi-jose/compare/1.5.0...1.6.0) (2022-09-09)


### Features

* add 'compact_sign_json' rust function ([cbe8ee6](https://github.com/NuggetsLtd/ffi-jose/commit/cbe8ee68c4fb04be9e26edbe8a96c99b6dc5e586))
* add 'compactJsonVerify' ffi from rust binary ([61be0b8](https://github.com/NuggetsLtd/ffi-jose/commit/61be0b8cb477806935c3f55baba25b3f8897ff98))
* add 'compactSignJson' ffi to rust binary ([3b6069b](https://github.com/NuggetsLtd/ffi-jose/commit/3b6069bd460512ddc282145647d9b1f6b521c874))
* add 'flattenedSignJson' ffi from rust binary ([e35a13e](https://github.com/NuggetsLtd/ffi-jose/commit/e35a13efa976422638a164e2e0124bd206f2e146))
* add 'generalSignJson' ffi from rust binary ([47c1ad9](https://github.com/NuggetsLtd/ffi-jose/commit/47c1ad99676bea74c9db7a90f1cdb435ed39bf96))
* add 'jsonVerify' ffi from rust binary ([fe52a59](https://github.com/NuggetsLtd/ffi-jose/commit/fe52a59169a3e55e69d6146d8563a41fdb7e40fe))
* add 'rust_flattened_sign_json' function ([8017cd0](https://github.com/NuggetsLtd/ffi-jose/commit/8017cd00c1b33d34ff75cd1990162320c3c3b12b))
* add 'rust_general_sign_json' function ([34970fa](https://github.com/NuggetsLtd/ffi-jose/commit/34970fa3e07753885cc9ccd696e306311dc47ae2))
* add 'rust_json_verify' function ([41b5685](https://github.com/NuggetsLtd/ffi-jose/commit/41b56853c34b9bc84ba33bca7edac6ca7866e4a9))
* add 'SigningAlgorithm' type ([a12ff86](https://github.com/NuggetsLtd/ffi-jose/commit/a12ff86210db48dc79d7a9558a223495e7f79675))
* add node FFI for 'compact_sign_json' ([a31186a](https://github.com/NuggetsLtd/ffi-jose/commit/a31186a68c9778378ea378f5e6229caaae82ccfe))
* neon 'compact_json_verify' ffi ([9f1ede3](https://github.com/NuggetsLtd/ffi-jose/commit/9f1ede3f16ef98aa8321fd812cb4d8edba75743f))
* neon FFI for flattened and general signing & verificaiton ([930e888](https://github.com/NuggetsLtd/ffi-jose/commit/930e888c59910804fd66e712ddd1879c39c6546b))
* rust implementation for 'rust_compact_json_verify' fn ([1e1f209](https://github.com/NuggetsLtd/ffi-jose/commit/1e1f209a69c977aca0fb28674e16a7f4e378e8ec))



# [1.5.0](https://github.com/NuggetsLtd/ffi-jose/compare/v1.3.0...v1.5.0) (2022-09-05)



# 1.3.0 (2022-08-19)


### Features

* initial commit (using  as template) ([2fa1e36](https://github.com/NuggetsLtd/ffi-jose/commit/2fa1e36be226db04c74623c78397a5c7a0190790))



# 1.2.0 (2022-08-19)


### Features

* initial commit (using  as template) ([2fa1e36](https://github.com/NuggetsLtd/ffi-jose/commit/2fa1e36be226db04c74623c78397a5c7a0190790))



