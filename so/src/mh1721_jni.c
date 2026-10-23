#include "mh1721_crypto.h"

#include <jni.h>
#include <stdlib.h>
#include <string.h>

static int copy_array(JNIEnv *env, jbyteArray arr, uint8_t **out, int *out_len) {
    jsize n;
    uint8_t *buf;

    if (!arr) {
        return -1;
    }
    n = (*env)->GetArrayLength(env, arr);
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    buf = (uint8_t *)malloc((size_t)n);
    if (!buf) {
        return -1;
    }
    (*env)->GetByteArrayRegion(env, arr, 0, n, (jbyte *)buf);
    *out = buf;
    *out_len = (int)n;
    return 0;
}

static jbyteArray to_array(JNIEnv *env, const uint8_t *data, int len) {
    jbyteArray arr = (*env)->NewByteArray(env, len);
    if (arr && len > 0) {
        (*env)->SetByteArrayRegion(env, arr, 0, len, (const jbyte *)data);
    }
    return arr;
}

static jbyteArray rsa_call(JNIEnv *env, jbyteArray modulus, jbyteArray exponent, jbyteArray data,
                           int (*fn)(const uint8_t *, int, const uint8_t *, int, const uint8_t *, int, uint8_t *, int)) {
    uint8_t *mod = NULL;
    uint8_t *exp = NULL;
    uint8_t *in = NULL;
    uint8_t *out = NULL;
    int mod_len = 0;
    int exp_len = 0;
    int in_len = 0;
    int n;
    jbyteArray result = NULL;

    if (copy_array(env, modulus, &mod, &mod_len) != 0 ||
        copy_array(env, exponent, &exp, &exp_len) != 0 ||
        copy_array(env, data, &in, &in_len) != 0) {
        goto done;
    }
    out = (uint8_t *)malloc((size_t)mod_len);
    if (!out) {
        goto done;
    }
    n = fn(mod, mod_len, exp, exp_len, in, in_len, out, mod_len);
    if (n >= 0) {
        result = to_array(env, out, n);
    }

done:
    free(mod);
    if (exp) {
        memset(exp, 0, (size_t)exp_len);
        free(exp);
    }
    free(in);
    if (out) {
        memset(out, 0, (size_t)mod_len);
        free(out);
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_mh1721_crypto_Mh1721Crypto_encrypt(JNIEnv *env, jclass clazz,
                                           jbyteArray modulus, jbyteArray exponent, jbyteArray data) {
    (void)clazz;
    return rsa_call(env, modulus, exponent, data, mh1721_rsa_encrypt);
}

JNIEXPORT jbyteArray JNICALL
Java_com_mh1721_crypto_Mh1721Crypto_decrypt(JNIEnv *env, jclass clazz,
                                           jbyteArray modulus, jbyteArray exponent, jbyteArray data) {
    (void)clazz;
    return rsa_call(env, modulus, exponent, data, mh1721_rsa_decrypt);
}

JNIEXPORT jbyteArray JNICALL
Java_com_mh1721_crypto_Mh1721Crypto_sign(JNIEnv *env, jclass clazz,
                                        jbyteArray modulus, jbyteArray exponent, jbyteArray data) {
    (void)clazz;
    return rsa_call(env, modulus, exponent, data, mh1721_rsa_sign);
}

JNIEXPORT jboolean JNICALL
Java_com_mh1721_crypto_Mh1721Crypto_verify(JNIEnv *env, jclass clazz,
                                          jbyteArray modulus, jbyteArray exponent,
                                          jbyteArray data, jbyteArray signature) {
    uint8_t *mod = NULL;
    uint8_t *exp = NULL;
    uint8_t *in = NULL;
    uint8_t *sig = NULL;
    int mod_len = 0;
    int exp_len = 0;
    int in_len = 0;
    int sig_len = 0;
    int rc = -1;

    (void)clazz;
    if (copy_array(env, modulus, &mod, &mod_len) == 0 &&
        copy_array(env, exponent, &exp, &exp_len) == 0 &&
        copy_array(env, data, &in, &in_len) == 0 &&
        copy_array(env, signature, &sig, &sig_len) == 0) {
        rc = mh1721_rsa_verify(mod, mod_len, exp, exp_len, in, in_len, sig, sig_len);
    }
    free(mod);
    if (exp) {
        memset(exp, 0, (size_t)exp_len);
        free(exp);
    }
    free(in);
    free(sig);
    return rc == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_mh1721_crypto_Mh1721Crypto_version(JNIEnv *env, jclass clazz) {
    (void)clazz;
    return (*env)->NewStringUTF(env, mh1721_version());
}
