#ifndef MH_RSA_H
#define MH_RSA_H

/*
 * Same names and layout as the MH1721 cryptolib in mh_rsa.h.
 * Compile bn.c, bn_arith.c, and mh_rsa.c into the firmware and call these
 * instead of the ROM library. Pub and Pri are raw modular exponentiation:
 * output = input ^ exponent mod N, with no PKCS#1 padding.
 *
 * Numbers are unsigned big-endian, placed at the start of each buffer.
 * N and D are u32NBits/8 bytes. E is u32EBits/8 bytes. P, Q, Dp, Dq, and Qi
 * are half of N. u32NBits is 512 to 2048 and a multiple of 16.
 *
 * GenKey reads random bytes from mh_random(). On the chip, implement that
 * with the hardware RNG and do not compile random.c.
 */

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define MH_RSA_API __attribute__((visibility("default")))
#else
#define MH_RSA_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MH_RET_RSA_INIT                 0x52865900u
#define MH_RET_RSA_SUCCESS              0x528659AAu
#define MH_RET_RSA_PARAM_ERR            (MH_RET_RSA_INIT + 0x001u)
#define MH_RET_RSA_TRNG_ERR             (MH_RET_RSA_INIT + 0x002u)
#define MH_RET_RSA_ERR                  (MH_RET_RSA_INIT + 0x003u)
#define MH_RET_RSA_LOCK                 (MH_RET_RSA_INIT + 0x004u)
#define MH_RET_RSA_PRIME_NOT_ACCEPTABLE (MH_RET_RSA_INIT + 0x005u)
#define MH_RET_RSA_GCD_ISNOT_ONE        (MH_RET_RSA_INIT + 0x006u)
#define MH_RET_RSA_PATH_CHECK_FAIL      (MH_RET_RSA_INIT + 0x007u)
#define MH_RET_RSA_DPA_LOCK             (MH_RET_RSA_INIT + 0x008u)

#define MH_RSA_COMPLETE_E   0u
#define MH_RSA_COMPLETE_D   1u
#define MH_RSA_COMPLETE_CRT 2u

#define MH_RSA_GENKEY_EFC  0u
#define MH_RSA_GENKEY_GENE 1u

#define IS_RSA_COMPLETE_TYPE(TYPE) \
    (((TYPE) == MH_RSA_COMPLETE_E) || ((TYPE) == MH_RSA_COMPLETE_D) || ((TYPE) == MH_RSA_COMPLETE_CRT))
#define IS_RSA_GENKEY_TYPE(TYPE) \
    (((TYPE) == MH_RSA_GENKEY_EFC) || ((TYPE) == MH_RSA_GENKEY_GENE))

/* Caller buffer for MHRSA_SetKey / MHRSA_GenKey / MHRSA_CompleteKey when pu8Base is not NULL. */
#define MH_RSA_BASE_BYTES 1536

typedef struct {
    uint32_t u32NBits;
    uint32_t u32EBits;
    uint8_t *pu8N;
    uint8_t *pu8E;
    uint8_t *pu8D;
    uint8_t *pu8P;
    uint8_t *pu8Q;
    uint8_t *pu8Dp;
    uint8_t *pu8Dq;
    uint8_t *pu8Qi;
    uint32_t u32Crc;
} MH_RSA_KEY;

/* Opaque 12-word workspace. The caller owns this memory. */
typedef struct {
    uint32_t au32Reserve[12];
} MH_RSA_KEY_SPACE;

typedef struct {
    uint8_t *pu8Input;
    uint8_t *pu8Output;
    uint32_t u32InLen;
    uint32_t u32OutLen;
    uint32_t u32Crc;
    MH_RSA_KEY_SPACE *KeyBase;
} MH_RSA_CALL;

MH_RSA_API uint32_t MHRSA_Init(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase);
MH_RSA_API uint32_t MHRSA_SetKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase, uint8_t *pu8Base);
MH_RSA_API uint32_t MHRSA_CompleteKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase,
                                     uint8_t *pu8Base, uint32_t u32CompType);
MH_RSA_API uint32_t MHRSA_GenKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase,
                                uint8_t *pu8Base, uint32_t u32GenKeyType);
MH_RSA_API uint32_t MHRSA_Pub(MH_RSA_CALL *pCall);
MH_RSA_API uint32_t MHRSA_Pri(MH_RSA_CALL *pCall);
MH_RSA_API uint32_t MHRSA_CrtPri(MH_RSA_CALL *pCall);

#ifdef __cplusplus
}
#endif

#endif
