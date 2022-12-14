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
 * Signature: (II[B[BZ)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_general_1encrypt_1json
  (JNIEnv *, jclass, jint, jint, jbyteArray, jbyteArray, jboolean);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    decrypt_json
 * Signature: ([B[B)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_decrypt_1json
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    compact_sign_json
 * Signature: (I[B[BZ)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_compact_1sign_1json
  (JNIEnv *, jclass, jint, jbyteArray, jbyteArray, jboolean);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    compact_json_verify
 * Signature: ([B[B)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_compact_1json_1verify
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    flattened_sign_json
 * Signature: (I[B[BZ)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_flattened_1sign_1json
  (JNIEnv *, jclass, jint, jbyteArray, jbyteArray, jboolean);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    json_verify
 * Signature: ([B[B)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_json_1verify
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     life_nuggets_rs_Jose
 * Method:    general_sign_json
 * Signature: ([B[BZ)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_life_nuggets_rs_Jose_general_1sign_1json
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jboolean);

#ifdef __cplusplus
}
#endif
#endif
