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
  JwkJsonString json_string;

  int outcome = ffi_jose_generate_key_pair_jwk(named_curve, &json_string);

  if (outcome == 0)
  {
    printf("Generated JWK:\n%s\n\n", json_string.ptr);
  }

  ffi_jose_free_jwk_string(json_string);
}

void encryptMsg(ContentEncryptionAlgorithm enc, char* key, char* iv, char* plaintext)
{
  EncryptedJsonString json_string;
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

  ffi_jose_free_encrypted_string(json_string);
}

void decryptMsg(ContentEncryptionAlgorithm enc, char* key, char* ciphertext, char* iv, char* tag)
{
  DecryptedString json_string;
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

  ffi_jose_free_decrypted_string(json_string);
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
  char* plaintext = "MESSAGE_TO_ENCRYPT";
  encryptMsg(A128gcm, key, iv, plaintext);

  char* ciphertext = "862dc0141058b5ca4768f7928a3c93fa35c6";
  char* tag = "aba4fd9f3ab9dde676f7b1a91f562b35";
  decryptMsg(A128gcm, key, ciphertext, iv, tag);
}
