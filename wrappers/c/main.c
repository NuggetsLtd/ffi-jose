#include <stdio.h>
#include <string.h>
#include "libjose.h"

typedef unsigned char BYTE;

void string2ByteArray(char* input, BYTE* output)
{
    int loop;
    int i;
    
    loop = 0;
    i = 0;
    
    while(input[loop] != '\0')
    {
        output[i++] = input[loop++];
    }
}

void generateKeyPairJWK(NamedCurve named_curve)
{
  JsonString json_string;

  int outcome = ffi_jose_generate_key_pair_jwk(named_curve, &json_string);

  if (outcome == 0)
  {
    printf("Generated JWK:\n%s\n\n", json_string.ptr);
  }

  ffi_jose_free_json_string(json_string);
}

void encryptMsg(ContentEncryptionAlgorithm enc, char* key, char* iv, char* plaintext)
{
  JsonString json_string;
  ByteArray keyBuffer;
  ByteArray ivBuffer;
  ByteArray messageBuffer;
  ByteArray aadBuffer;

  // convert key from hex to byte array
  char *keyPos = key;
  keyBuffer.length = ( strlen(key) / 2 );
  unsigned char keyBufferData[keyBuffer.length];
  for (size_t count = 0; count < sizeof keyBufferData/sizeof *keyBufferData; count++) {
      sscanf(keyPos, "%2hhx", &keyBufferData[count]);
      keyPos += 2;
  }
  keyBuffer.data = keyBufferData;

  // convert iv from hex to byte array
  char *ivPos = iv;
  ivBuffer.length = ( strlen(iv) / 2 );
  unsigned char ivBufferData[ivBuffer.length];
  for (size_t count = 0; count < sizeof ivBufferData/sizeof *ivBufferData; count++) {
      sscanf(ivPos, "%2hhx", &ivBufferData[count]);
      ivPos += 2;
  }
  ivBuffer.data = ivBufferData;

  // populate message buffer
  BYTE messageBufferData[strlen(plaintext)];
  string2ByteArray(plaintext, messageBufferData);
  messageBuffer.length = strlen(plaintext);
  messageBuffer.data = messageBufferData;

  // set aad buffer as empty
  aadBuffer.length = 0;

  int outcome = ffi_jose_encrypt(enc, keyBuffer, ivBuffer, messageBuffer, aadBuffer, &json_string);

  if (outcome == 0)
  {
    printf("Encrypted Msg:\n%s\n\n", json_string.ptr);
  }

  ffi_jose_free_json_string(json_string);
}

void decryptMsg(ContentEncryptionAlgorithm enc, char* key, char* ciphertext, char* iv, char* tag)
{
  JsonString json_string;
  ByteArray keyBuffer;
  ByteArray ciphertextBuffer;
  ByteArray ivBuffer;
  ByteArray tagBuffer;
  ByteArray aadBuffer;

  // convert key from hex to byte array
  char *keyPos = key;
  keyBuffer.length = ( strlen(key) / 2 );
  unsigned char keyBufferData[keyBuffer.length];
  for (size_t count = 0; count < sizeof keyBufferData/sizeof *keyBufferData; count++) {
      sscanf(keyPos, "%2hhx", &keyBufferData[count]);
      keyPos += 2;
  }
  keyBuffer.data = keyBufferData;

  // convert iv from hex to byte array
  char *ivPos = iv;
  ivBuffer.length = ( strlen(iv) / 2 );
  unsigned char ivBufferData[ivBuffer.length];
  for (size_t count = 0; count < sizeof ivBufferData/sizeof *ivBufferData; count++) {
      sscanf(ivPos, "%2hhx", &ivBufferData[count]);
      ivPos += 2;
  }
  ivBuffer.data = ivBufferData;

  // convert ciphertext from hex to byte array
  char *ciphertextPos = ciphertext;
  ciphertextBuffer.length = ( strlen(ciphertext) / 2 );
  unsigned char ciphertextBufferData[ciphertextBuffer.length];
  for (size_t count = 0; count < sizeof ciphertextBufferData/sizeof *ciphertextBufferData; count++) {
      sscanf(ciphertextPos, "%2hhx", &ciphertextBufferData[count]);
      ciphertextPos += 2;
  }
  ciphertextBuffer.data = ciphertextBufferData;

  // convert tag from hex to byte array
  char *tagPos = tag;
  tagBuffer.length = ( strlen(tag) / 2 );
  unsigned char tagBufferData[tagBuffer.length];
  for (size_t count = 0; count < sizeof tagBufferData/sizeof *tagBufferData; count++) {
      sscanf(tagPos, "%2hhx", &tagBufferData[count]);
      tagPos += 2;
  }
  tagBuffer.data = tagBufferData;

  // set aad buffer as empty
  aadBuffer.length = 0;

  int outcome = ffi_jose_decrypt(enc, keyBuffer, ciphertextBuffer, ivBuffer, tagBuffer, aadBuffer, &json_string);

  if (outcome == 0)
  {
    printf("Decrypted Msg (Base64):\n%s\n\n", json_string.ptr);
  }

  ffi_jose_free_json_string(json_string);
}

void generalEncryptJson(KeyEncryptionAlgorithm alg, ContentEncryptionAlgorithm enc, char* recipients, char* payload)
{
  JsonString json_string;
  ByteArray recipientsBuffer;
  ByteArray payloadBuffer;

  // populate recipients buffer
  recipientsBuffer.length = strlen(recipients);
  BYTE recipientsBufferData[recipientsBuffer.length];
  string2ByteArray(recipients, recipientsBufferData);
  recipientsBuffer.data = recipientsBufferData;

  // populate payload buffer
  payloadBuffer.length = strlen(payload);
  BYTE payloadBufferData[payloadBuffer.length];
  string2ByteArray(payload, payloadBufferData);
  payloadBuffer.data = payloadBufferData;

  int outcome = ffi_jose_general_encrypt_json(alg, enc, payloadBuffer, recipientsBuffer, &json_string);

  if (outcome == 0)
  {
    printf("General Encrypted Msg:\n%s\n\n", json_string.ptr);
  }

  ffi_jose_free_json_string(json_string);
}

void decryptJson(char* jwe, char* jwk)
{
  JsonString json_string;
  ByteArray jweBuffer;
  ByteArray jwkBuffer;

  // populate jwe buffer
  jweBuffer.length = strlen(jwe);
  BYTE jweBufferData[jweBuffer.length];
  string2ByteArray(jwe, jweBufferData);
  jweBuffer.data = jweBufferData;

  // populate jwk buffer
  jwkBuffer.length = strlen(jwk);
  BYTE jwkBufferData[jwkBuffer.length];
  string2ByteArray(jwk, jwkBufferData);
  jwkBuffer.data = jwkBufferData;

  int outcome = ffi_jose_decrypt_json(jweBuffer, jwkBuffer, &json_string);

  if (outcome == 0)
  {
    printf("Decrypted Msg:\n%s\n\n", json_string.ptr);
  }

  ffi_jose_free_json_string(json_string);
}

void compactSignJson(SigningAlgorithm alg, char* jwk, char* payload)
{
  JsonString json_string;
  ByteArray payloadBuffer;
  ByteArray jwkBuffer;

  // populate jwk buffer
  jwkBuffer.length = strlen(jwk);
  BYTE jwkBufferData[jwkBuffer.length];
  string2ByteArray(jwk, jwkBufferData);
  jwkBuffer.data = jwkBufferData;

  // populate payload buffer
  payloadBuffer.length = strlen(payload);
  BYTE payloadBufferData[payloadBuffer.length];
  string2ByteArray(payload, payloadBufferData);
  payloadBuffer.data = payloadBufferData;

  int outcome = ffi_jose_compact_sign_json(alg, payloadBuffer, jwkBuffer, &json_string);

  if (outcome == 0)
  {
    printf("Compact Signed Msg:\n%s\n\n", json_string.ptr);
  }

  ffi_jose_free_json_string(json_string);
}

void verifyCompactJson(char* jws, char* jwk)
{
  JsonString json_string;
  ByteArray jwsBuffer;
  ByteArray jwkBuffer;

  // populate jws buffer
  jwsBuffer.length = strlen(jws);
  BYTE jwsBufferData[jwsBuffer.length];
  string2ByteArray(jws, jwsBufferData);
  jwsBuffer.data = jwsBufferData;

  // populate jwk buffer
  jwkBuffer.length = strlen(jwk);
  BYTE jwkBufferData[jwkBuffer.length];
  string2ByteArray(jwk, jwkBufferData);
  jwkBuffer.data = jwkBufferData;

  int outcome = ffi_jose_compact_json_verify(jwsBuffer, jwkBuffer, &json_string);

  if (outcome == 0)
  {
    printf("Verified Msg:\n%s\n\n", json_string.ptr);
  }

  ffi_jose_free_json_string(json_string);
}

int main()
{
  generateKeyPairJWK(P256);
  generateKeyPairJWK(P384);
  generateKeyPairJWK(P521);
  generateKeyPairJWK(Secp256k1);
  generateKeyPairJWK(Ed25519);
  generateKeyPairJWK(Ed448);
  generateKeyPairJWK(X25519);
  generateKeyPairJWK(X448);

  char* key = "b8aae648b9c7819e24f2b2c684efcef1";
  char* iv = "eae7e2df51f0dc34c39183e8";
  char* plaintext = "PLAINTEXT";
  encryptMsg(A128gcm, key, iv, plaintext);

  char* ciphertext = "862dc0141058b5ca4768f7928a3c93fa35c6";
  char* tag = "aba4fd9f3ab9dde676f7b1a91f562b35";
  decryptMsg(A128gcm, key, ciphertext, iv, tag);

  char* recipientsSingle = "[{\"kid\":\"did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"A4NKTvWeEv3b-sJnlmwrATDklidT_qo3jTYRV2shaAc\",\"y\":\"_06GxhBcbxJzOCTz4F0kq_mETgGti33WkFpMKZHc-SY\"}]";
  generalEncryptJson(EcdhEsA256kw, A128gcm, recipientsSingle, plaintext);

  char* recipientsMultiple = "[{\"kid\":\"did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"A4NKTvWeEv3b-sJnlmwrATDklidT_qo3jTYRV2shaAc\",\"y\":\"_06GxhBcbxJzOCTz4F0kq_mETgGti33WkFpMKZHc-SY\"},{\"kid\":\"did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p256-1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"YQbhZhp4ORKjwMqQIGFbIVSyYaaBuJbym_UWEWJPgbM\",\"y\":\"hxHEiOwPXUt1Nv_3MO5oRkUoMtYFaWIzW0iiZMNTnFE\"}]";
  generalEncryptJson(EcdhEsA256kw, A128gcm, recipientsMultiple, plaintext);

  char* jwe1 = "{\"protected\":\"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkExMjhHQ00iLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0\",\"recipients\":[{\"header\":{\"kid\":\"did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1\",\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"gOck1VTJKClbIBckxyWDcvjgH7Hjh8l8JtZyMF_pcUg\",\"y\":\"erdiGdGNx_Bq3ZjIP0O6HqwnZ-hV4Qla1143vHg2CtA\"}},\"encrypted_key\":\"mYei_90yBUye5t54StnQWyZmpzgoaQ9N\"}],\"iv\":\"r7Tgd038slI_oE7v\",\"ciphertext\":\"0CPqmVTEOU3r\",\"tag\":\"WHzSP6R0tUK-w4UD1twngQ\"}";
  char* jwk1 = "{\"kid\":\"did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"qjx4ib5Ea94YnyypBBPnvtGUuoRgGtF_0BtPuOSMJPc\"}";
  decryptJson(jwe1, jwk1);

  char* jwe2 = "{\"protected\":\"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkExMjhHQ00iLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0\",\"recipients\":[{\"header\":{\"kid\":\"did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1\",\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"KEt3oBE9bpsu3meaYQvRmF_y6zNtml4ziN3fXq4Tpa8\",\"y\":\"qtoKMfk5bxo4_TEGz1GCJSwanNtt-enZvuWUi_42Pko\"}},\"encrypted_key\":\"8H45Ib-7SB8hFPBF7adVCt0fm1su4WZ_\"},{\"header\":{\"kid\":\"did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p256-1\",\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"7Xdm9ui6DV3yT10oUe3kl-NAisnywvVTFp0TVo9ILVg\",\"y\":\"HcC88ngI0gHAKp7GR-a4E_VDEgqpnKs-yfgt0Lx-Lgw\"}},\"encrypted_key\":\"nPbYDVJPcL1w1aZsikU8uXwCwppGlvC4\"}],\"iv\":\"8flfc6gEcmROAsIq\",\"ciphertext\":\"jZ5hTy5pxSb0\",\"tag\":\"pfGFGYwsOcke0QrrT04Izw\"}";
  char* jwk2 = "{\"kid\":\"did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p256-1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"pndx4RjZSMpYjkokcn5xcIfmhZV19-jr_0n4l1kcphI\"}";
  decryptJson(jwe2, jwk2);

  char* signer_jwk = "{\"kid\":\"did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"-uGB3yMayMJbhAolwzVzdjchW0W2i3pYZOii2N7Wg88\"}";
  char* payload = "{\"hello\":\"you\"}";
  compactSignJson(Es256, signer_jwk, payload);

  char* verifier_jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"t2aXVivRDLhttpb8bKWLmn73eaNj3xOaWgP405z7pjU\",\"y\":\"YSjJhceBD_GaCTns1UNLSVvxXPziftTcEv7LSG6AxcE\"}";
  char* jws_compact = "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRVMyNTYifQ.eyJoZWxsbyI6InlvdSJ9.sfs9z4cJS1x75STCNvot50tGzg6zo8bvW2lP3rJzIfnCD9NO2_GNNL8l0BhXEeIhapHq7Tma-Ys0iQWNL2PpAw";
  verifyCompactJson(jws_compact, verifier_jwk);
}
