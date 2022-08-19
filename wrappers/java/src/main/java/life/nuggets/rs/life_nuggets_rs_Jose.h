/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class life_nuggets_rs_Jose */

#ifndef _Included_life_nuggets_rs_Jose
#define _Included_life_nuggets_rs_Jose
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     life_nuggets_rs_Jose
 * Method:    generate_key_pair_jwk
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_generate_1key_1pair_1jwk
  (JNIEnv *, jclass, jint);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    generate_key_pair
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_generate_1key_1pair
  (JNIEnv *, jclass, jint);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    encrypt
 * Signature: (I[B[B[B[B)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_encrypt
  (JNIEnv *, jclass, jint, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    decrypt
 * Signature: (I[B[B[B[B[B)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_decrypt
  (JNIEnv *, jclass, jint, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    general_encrypt_json
 * Signature: (II[B[B)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_general_1encrypt_1json
  (JNIEnv *, jclass, jint, jint, jbyteArray, jbyteArray);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    decrypt_json
 * Signature: ([B[B)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_decrypt_1json
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif