#ifndef MH1721_CRYPTO_H
#define MH1721_CRYPTO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define MH1721_API __attribute__((visibility("default")))
#else
#define MH1721_API
#endif

/*
 * PKCS#1 v1.5 RSA. Modulus and exponents are unsigned big-endian.
 * A leading 0x00 byte is ignored, so Java BigInteger.toByteArray() works.
 * Modulus size is 64 to 512 bytes (512 to 4096 bits).
 * Encrypt and decrypt use type-2 padding. Sign and verify hash with SHA-256
 * and use type-1 padding. Returns the byte length written, or -1.
 * Verify returns 0 when the signature matches, or -1.
 */
MH1721_API int mh1721_rsa_encrypt(const uint8_t *modulus, int modulus_len,
                                  const uint8_t *exponent, int exponent_len,
                                  const uint8_t *in, int in_len,
                                  uint8_t *out, int out_cap);
MH1721_API int mh1721_rsa_decrypt(const uint8_t *modulus, int modulus_len,
                                  const uint8_t *exponent, int exponent_len,
                                  const uint8_t *in, int in_len,
                                  uint8_t *out, int out_cap);
MH1721_API int mh1721_rsa_sign(const uint8_t *modulus, int modulus_len,
                               const uint8_t *exponent, int exponent_len,
                               const uint8_t *in, int in_len,
                               uint8_t *out, int out_cap);
MH1721_API int mh1721_rsa_verify(const uint8_t *modulus, int modulus_len,
                                 const uint8_t *exponent, int exponent_len,
                                 const uint8_t *in, int in_len,
                                 const uint8_t *signature, int signature_len);

MH1721_API const char *mh1721_version(void);

#ifdef __cplusplus
}
#endif

#endif
