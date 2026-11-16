#include "mh_rsa.h"
#include "mh1721_internal.h"

#include <string.h>

#define RSA_MAGIC 0x52534131u

typedef struct {
    uint32_t magic;
    uint32_t nbits;
    uint32_t ebits;
    uint32_t flags;
    uint32_t crc;
    uint32_t nbytes;
    uint32_t half;
    uint32_t ptr_lo;
    uint32_t ptr_hi;
    uint32_t reserved;
} rsa_slot;

enum {
    PART_N = 0,
    PART_E,
    PART_D,
    PART_P,
    PART_Q,
    PART_DP,
    PART_DQ,
    PART_QI
};

#define FLAG_D   1u
#define FLAG_CRT 2u

static uint8_t internal_store[MH_RSA_BASE_BYTES];

static void slot_load(rsa_slot *slot, const MH_RSA_KEY_SPACE *base) {
    memset(slot, 0, sizeof(*slot));
    memcpy(slot, base, sizeof(*slot));
}

static void slot_store(MH_RSA_KEY_SPACE *base, const rsa_slot *slot) {
    memset(base, 0, sizeof(*base));
    memcpy(base, slot, sizeof(*slot));
}

static uint8_t *slot_bytes(const rsa_slot *slot) {
    uintptr_t pointer = (uintptr_t)slot->ptr_lo;
    pointer |= (uintptr_t)slot->ptr_hi << 32;
    return (uint8_t *)pointer;
}

static void set_pointer(rsa_slot *slot, uint8_t *storage) {
    uintptr_t pointer = (uintptr_t)storage;
    slot->ptr_lo = (uint32_t)pointer;
    slot->ptr_hi = (uint32_t)(pointer >> 32);
}

static int widths(uint32_t nbits, int *nbytes, int *half) {
    if (nbits < 512 || nbits > 2048 || (nbits % 16u) != 0) {
        return -1;
    }
    *nbytes = (int)(nbits / 8u);
    *half = *nbytes / 2;
    if (*nbytes * 3 + *half * 5 > MH_RSA_BASE_BYTES) {
        return -1;
    }
    return 0;
}

static uint8_t *part(uint8_t *base, int nbytes, int half, int id) {
    switch (id) {
    case PART_N:
        return base;
    case PART_E:
        return base + nbytes;
    case PART_D:
        return base + 2 * nbytes;
    case PART_P:
        return base + 3 * nbytes;
    case PART_Q:
        return base + 3 * nbytes + half;
    case PART_DP:
        return base + 3 * nbytes + 2 * half;
    case PART_DQ:
        return base + 3 * nbytes + 3 * half;
    default:
        return base + 3 * nbytes + 4 * half;
    }
}

static int read_fixed(mh_bn *out, const uint8_t *src, int len) {
    if (!src || len <= 0) {
        return -1;
    }
    return mh_bn_from_be(out, src, len);
}

static int write_fixed(const mh_bn *value, uint8_t *dst, int len) {
    if (!dst) {
        return 0;
    }
    return mh_bn_to_be(value, dst, len);
}

static uint32_t crc32_bytes(const uint8_t *data, int len) {
    uint32_t crc = 0xffffffffu;
    int i;
    for (i = 0; i < len; i++) {
        int bit;
        crc ^= data[i];
        for (bit = 0; bit < 8; bit++) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (0xedb88320u & mask);
        }
    }
    return ~crc;
}

static int load_part(mh_bn *out, const rsa_slot *slot, int id) {
    uint8_t *base = slot_bytes(slot);
    int len = (id == PART_E || id == PART_N || id == PART_D) ? (int)slot->nbytes : (int)slot->half;
    if (id == PART_E) {
        len = (int)((slot->ebits + 7u) / 8u);
        if (len > (int)slot->nbytes) {
            len = (int)slot->nbytes;
        }
    }
    return read_fixed(out, part(base, (int)slot->nbytes, (int)slot->half, id), len);
}

static uint32_t install(MH_RSA_KEY *key, MH_RSA_KEY_SPACE *keybase, uint8_t *storage,
                        const mh_bn *n, const mh_bn *e, const mh_bn *d,
                        const mh_bn *p, const mh_bn *q, const mh_bn *dp,
                        const mh_bn *dq, const mh_bn *qi) {
    rsa_slot slot;
    int nbytes = 0;
    int half = 0;
    int elen;
    uint8_t *base;
    memset(&slot, 0, sizeof(slot));
    if (widths(key->u32NBits, &nbytes, &half) != 0 || mh_bn_is_zero(n) || mh_bn_is_zero(e)) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (key->u32EBits < 2 || (key->u32EBits + 7u) / 8u > (uint32_t)nbytes) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if ((n->d[0] & 1u) == 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    base = storage ? storage : internal_store;
    memset(base, 0, MH_RSA_BASE_BYTES);
    if (write_fixed(n, part(base, nbytes, half, PART_N), nbytes) != 0 ||
        write_fixed(e, part(base, nbytes, half, PART_E), (int)((key->u32EBits + 7u) / 8u)) != 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    elen = (int)((key->u32EBits + 7u) / 8u);
    if (d && !mh_bn_is_zero(d)) {
        if (write_fixed(d, part(base, nbytes, half, PART_D), nbytes) != 0) {
            return MH_RET_RSA_PARAM_ERR;
        }
        slot.flags |= FLAG_D;
    }
    if (p && q && dp && dq && qi &&
        !mh_bn_is_zero(p) && !mh_bn_is_zero(q)) {
        if (write_fixed(p, part(base, nbytes, half, PART_P), half) != 0 ||
            write_fixed(q, part(base, nbytes, half, PART_Q), half) != 0 ||
            write_fixed(dp, part(base, nbytes, half, PART_DP), half) != 0 ||
            write_fixed(dq, part(base, nbytes, half, PART_DQ), half) != 0 ||
            write_fixed(qi, part(base, nbytes, half, PART_QI), half) != 0) {
            return MH_RET_RSA_PARAM_ERR;
        }
        slot.flags |= FLAG_CRT;
    }
    slot.magic = RSA_MAGIC;
    slot.nbits = key->u32NBits;
    slot.ebits = key->u32EBits;
    slot.nbytes = (uint32_t)nbytes;
    slot.half = (uint32_t)half;
    slot.crc = crc32_bytes(base, nbytes + elen);
    set_pointer(&slot, base);
    key->u32Crc = slot.crc;
    slot_store(keybase, &slot);
    return MH_RET_RSA_SUCCESS;
}

static uint32_t ready(const MH_RSA_CALL *call, rsa_slot *slot) {
    if (!call || !call->KeyBase || !call->pu8Input || !call->pu8Output || call->u32InLen == 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    slot_load(slot, call->KeyBase);
    if (slot->magic != RSA_MAGIC || !slot_bytes(slot)) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (call->u32Crc != 0 && call->u32Crc != slot->crc) {
        return MH_RET_RSA_PATH_CHECK_FAIL;
    }
    if (call->u32InLen > slot->nbytes || slot->nbytes > 512) {
        return MH_RET_RSA_PARAM_ERR;
    }
    return MH_RET_RSA_SUCCESS;
}

static uint32_t exponentiate(MH_RSA_CALL *call, const mh_bn *exp) {
    rsa_slot slot;
    mh_bn n;
    mh_bn base;
    uint8_t raw[512];
    uint32_t status;
    int written;
    status = ready(call, &slot);
    if (status != MH_RET_RSA_SUCCESS) {
        return status;
    }
    if (load_part(&n, &slot, PART_N) != 0 || mh_bn_from_be(&base, call->pu8Input, (int)call->u32InLen) != 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (mh_bn_cmp(&base, &n) >= 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    memset(raw, 0, sizeof(raw));
    written = mh_bn_modexp(&base, exp, &n, raw, (int)slot.nbytes);
    if (written < 0 || written > (int)slot.nbytes) {
        return MH_RET_RSA_ERR;
    }
    memset(call->pu8Output, 0, slot.nbytes);
    memcpy(call->pu8Output + (slot.nbytes - (uint32_t)written), raw, (size_t)written);
    call->u32OutLen = slot.nbytes;
    memset(raw, 0, sizeof(raw));
    return MH_RET_RSA_SUCCESS;
}

uint32_t MHRSA_Init(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase) {
    (void)pKeySrc;
    if (!pKeyBase) {
        return MH_RET_RSA_PARAM_ERR;
    }
    memset(pKeyBase, 0, sizeof(*pKeyBase));
    return MH_RET_RSA_SUCCESS;
}

uint32_t MHRSA_SetKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase, uint8_t *pu8Base) {
    mh_bn n;
    mh_bn e;
    mh_bn d;
    mh_bn p;
    mh_bn q;
    mh_bn dp;
    mh_bn dq;
    mh_bn qi;
    int nbytes = 0;
    int half = 0;
    int elen;
    int has_d = 0;
    int has_crt = 0;
    if (!pKeySrc || !pKeyBase || !pKeySrc->pu8N || !pKeySrc->pu8E) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (widths(pKeySrc->u32NBits, &nbytes, &half) != 0 || pKeySrc->u32EBits < 2) {
        return MH_RET_RSA_PARAM_ERR;
    }
    elen = (int)((pKeySrc->u32EBits + 7u) / 8u);
    if (read_fixed(&n, pKeySrc->pu8N, nbytes) != 0 || read_fixed(&e, pKeySrc->pu8E, elen) != 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    memset(&d, 0, sizeof(d));
    memset(&p, 0, sizeof(p));
    memset(&q, 0, sizeof(q));
    memset(&dp, 0, sizeof(dp));
    memset(&dq, 0, sizeof(dq));
    memset(&qi, 0, sizeof(qi));
    if (pKeySrc->pu8D) {
        if (read_fixed(&d, pKeySrc->pu8D, nbytes) != 0) {
            return MH_RET_RSA_PARAM_ERR;
        }
        has_d = !mh_bn_is_zero(&d);
    }
    if (pKeySrc->pu8P && pKeySrc->pu8Q && pKeySrc->pu8Dp && pKeySrc->pu8Dq && pKeySrc->pu8Qi) {
        if (read_fixed(&p, pKeySrc->pu8P, half) != 0 ||
            read_fixed(&q, pKeySrc->pu8Q, half) != 0 ||
            read_fixed(&dp, pKeySrc->pu8Dp, half) != 0 ||
            read_fixed(&dq, pKeySrc->pu8Dq, half) != 0 ||
            read_fixed(&qi, pKeySrc->pu8Qi, half) != 0) {
            return MH_RET_RSA_PARAM_ERR;
        }
        has_crt = !mh_bn_is_zero(&p) && !mh_bn_is_zero(&q);
    }
    return install(pKeySrc, pKeyBase, pu8Base, &n, &e, has_d ? &d : NULL,
                   has_crt ? &p : NULL, has_crt ? &q : NULL, has_crt ? &dp : NULL,
                   has_crt ? &dq : NULL, has_crt ? &qi : NULL);
}

static int lambda_of(mh_bn *lambda, mh_bn *pm1, mh_bn *qm1, const mh_bn *p, const mh_bn *q) {
    mh_bn one;
    mh_bn g;
    mh_bn quot;
    mh_bn rem;
    mh_bn_set_u32(&one, 1);
    if (mh_bn_sub(pm1, p, &one) != 0 || mh_bn_sub(qm1, q, &one) != 0) {
        return -1;
    }
    if (mh_bn_gcd(&g, pm1, qm1) != 0 || mh_bn_is_zero(&g)) {
        return -1;
    }
    if (mh_bn_divmod(&quot, &rem, pm1, &g) != 0 || !mh_bn_is_zero(&rem)) {
        return -1;
    }
    return mh_bn_mul(lambda, &quot, qm1);
}

static uint32_t fill_private(mh_bn *d, mh_bn *dp, mh_bn *dq, mh_bn *qi,
                             const mh_bn *e, const mh_bn *p, const mh_bn *q, int have_d) {
    mh_bn lambda;
    mh_bn pm1;
    mh_bn qm1;
    if (lambda_of(&lambda, &pm1, &qm1, p, q) != 0) {
        return MH_RET_RSA_ERR;
    }
    if (!have_d) {
        int inv = mh_bn_modinv(d, e, &lambda);
        if (inv == -2) {
            return MH_RET_RSA_GCD_ISNOT_ONE;
        }
        if (inv != 0) {
            return MH_RET_RSA_ERR;
        }
    }
    if (mh_bn_mod(dp, d, &pm1) != 0 || mh_bn_mod(dq, d, &qm1) != 0) {
        return MH_RET_RSA_ERR;
    }
    if (mh_bn_modinv(qi, q, p) != 0) {
        return MH_RET_RSA_ERR;
    }
    return MH_RET_RSA_SUCCESS;
}

static void publish(MH_RSA_KEY *key, int nbytes, int half,
                    const mh_bn *n, const mh_bn *e, const mh_bn *d,
                    const mh_bn *p, const mh_bn *q, const mh_bn *dp,
                    const mh_bn *dq, const mh_bn *qi) {
    int elen = (int)((key->u32EBits + 7u) / 8u);
    write_fixed(n, key->pu8N, nbytes);
    write_fixed(e, key->pu8E, elen);
    write_fixed(d, key->pu8D, nbytes);
    write_fixed(p, key->pu8P, half);
    write_fixed(q, key->pu8Q, half);
    write_fixed(dp, key->pu8Dp, half);
    write_fixed(dq, key->pu8Dq, half);
    write_fixed(qi, key->pu8Qi, half);
}

uint32_t MHRSA_CompleteKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase,
                          uint8_t *pu8Base, uint32_t u32CompType) {
    mh_bn p;
    mh_bn q;
    mh_bn e;
    mh_bn d;
    mh_bn n;
    mh_bn dp;
    mh_bn dq;
    mh_bn qi;
    int nbytes = 0;
    int half = 0;
    int have_d;
    uint32_t status;
    if (!pKeySrc || !pKeyBase || !IS_RSA_COMPLETE_TYPE(u32CompType) || !pKeySrc->pu8P || !pKeySrc->pu8Q) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (widths(pKeySrc->u32NBits, &nbytes, &half) != 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (read_fixed(&p, pKeySrc->pu8P, half) != 0 || read_fixed(&q, pKeySrc->pu8Q, half) != 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    memset(&e, 0, sizeof(e));
    memset(&d, 0, sizeof(d));
    if (u32CompType == MH_RSA_COMPLETE_E) {
        if (!pKeySrc->pu8D || read_fixed(&d, pKeySrc->pu8D, nbytes) != 0 || mh_bn_is_zero(&d)) {
            return MH_RET_RSA_PARAM_ERR;
        }
        have_d = 1;
    } else {
        int elen;
        if (!pKeySrc->pu8E || pKeySrc->u32EBits < 2) {
            return MH_RET_RSA_PARAM_ERR;
        }
        elen = (int)((pKeySrc->u32EBits + 7u) / 8u);
        if (read_fixed(&e, pKeySrc->pu8E, elen) != 0 || mh_bn_is_zero(&e)) {
            return MH_RET_RSA_PARAM_ERR;
        }
        have_d = 0;
        if (u32CompType == MH_RSA_COMPLETE_CRT && pKeySrc->pu8D) {
            if (read_fixed(&d, pKeySrc->pu8D, nbytes) != 0) {
                return MH_RET_RSA_PARAM_ERR;
            }
            have_d = !mh_bn_is_zero(&d);
        }
    }
    if (mh_bn_mul(&n, &p, &q) != 0) {
        return MH_RET_RSA_ERR;
    }
    if (u32CompType == MH_RSA_COMPLETE_E) {
        mh_bn lambda;
        mh_bn pm1;
        mh_bn qm1;
        int inv;
        if (lambda_of(&lambda, &pm1, &qm1, &p, &q) != 0) {
            return MH_RET_RSA_ERR;
        }
        inv = mh_bn_modinv(&e, &d, &lambda);
        if (inv == -2) {
            return MH_RET_RSA_GCD_ISNOT_ONE;
        }
        if (inv != 0) {
            return MH_RET_RSA_ERR;
        }
        pKeySrc->u32EBits = (uint32_t)(((mh_bn_bitlen(&e) + 31) / 32) * 32);
        if (pKeySrc->u32EBits < 2) {
            pKeySrc->u32EBits = 32;
        }
    }
    status = fill_private(&d, &dp, &dq, &qi, &e, &p, &q, have_d || u32CompType == MH_RSA_COMPLETE_E);
    if (status != MH_RET_RSA_SUCCESS) {
        return status;
    }
    publish(pKeySrc, nbytes, half, &n, &e, &d, &p, &q, &dp, &dq, &qi);
    return install(pKeySrc, pKeyBase, pu8Base, &n, &e, &d, &p, &q, &dp, &dq, &qi);
}

static const uint32_t SMALL_PRIMES[] = {
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97
};

static uint32_t mod_u32(const mh_bn *a, uint32_t m) {
    uint32_t r = 0;
    int i;
    for (i = a->n - 1; i >= 0; i--) {
        r = (uint32_t)(((uint64_t)r * 65536u + (a->d[i] >> 16)) % m);
        r = (uint32_t)(((uint64_t)r * 65536u + (a->d[i] & 0xffffu)) % m);
    }
    return r;
}

static int trial(const mh_bn *n) {
    size_t i;
    if ((n->d[0] & 1u) == 0) {
        return 0;
    }
    for (i = 0; i < sizeof(SMALL_PRIMES) / sizeof(SMALL_PRIMES[0]); i++) {
        if (n->n == 1 && n->d[0] == SMALL_PRIMES[i]) {
            return 1;
        }
        if (mod_u32(n, SMALL_PRIMES[i]) == 0) {
            return 0;
        }
    }
    return 1;
}

static int miller_rabin(const mh_bn *n) {
    mh_bn one;
    mh_bn nm1;
    mh_bn d;
    mh_bn two;
    int s = 0;
    int round;
    mh_bn_set_u32(&one, 1);
    mh_bn_set_u32(&two, 2);
    if (mh_bn_cmp(n, &two) < 0) {
        return 0;
    }
    if (mh_bn_sub(&nm1, n, &one) != 0) {
        return 0;
    }
    mh_bn_copy(&d, &nm1);
    while (!mh_bn_is_zero(&d) && (d.d[0] & 1u) == 0) {
        mh_bn_shr1(&d);
        s++;
    }
    for (round = 0; round < 8; round++) {
        mh_bn base;
        mh_bn x;
        uint8_t draw[64];
        int r;
        int matched = 0;
        if (round == 0) {
            mh_bn_set_u32(&base, 2);
        } else {
            if (mh_random(draw, (int)sizeof(draw)) != 0) {
                return -2;
            }
            if (mh_bn_from_be(&base, draw, (int)sizeof(draw)) != 0) {
                return -1;
            }
            if (mh_bn_mod(&base, &base, &nm1) != 0) {
                return -1;
            }
            if (mh_bn_cmp(&base, &two) < 0) {
                mh_bn_set_u32(&base, 2);
            }
        }
        if (mh_bn_modexp_bn(&x, &base, &d, n) != 0) {
            return -1;
        }
        if (mh_bn_cmp(&x, &one) == 0 || mh_bn_cmp(&x, &nm1) == 0) {
            continue;
        }
        for (r = 1; r < s; r++) {
            if (mh_bn_modexp_bn(&x, &x, &two, n) != 0) {
                return -1;
            }
            if (mh_bn_cmp(&x, &nm1) == 0) {
                matched = 1;
                break;
            }
            if (mh_bn_cmp(&x, &one) == 0) {
                return 0;
            }
        }
        if (!matched) {
            return 0;
        }
    }
    return 1;
}

static int probably_prime(const mh_bn *n) {
    int mr;
    if (!trial(n)) {
        return 0;
    }
    mr = miller_rabin(n);
    return mr;
}

static int gen_prime(mh_bn *prime, int bits) {
    int bytes = bits / 8;
    int attempt;
    uint8_t buf[128];
    if (bytes <= 0 || bytes > (int)sizeof(buf)) {
        return -1;
    }
    for (attempt = 0; attempt < 64; attempt++) {
        int step;
        if (mh_random(buf, bytes) != 0) {
            return -2;
        }
        buf[0] |= 0xc0;
        buf[bytes - 1] |= 0x01;
        if (mh_bn_from_be(prime, buf, bytes) != 0) {
            return -1;
        }
        for (step = 0; step < 2048; step++) {
            int prime_result;
            if (mh_bn_bitlen(prime) != bits) {
                break;
            }
            prime_result = probably_prime(prime);
            if (prime_result < 0) {
                return prime_result == -2 ? -2 : -1;
            }
            if (prime_result == 1) {
                return 0;
            }
            if (mh_bn_add_u32(prime, 2) != 0) {
                return -1;
            }
        }
    }
    return -3;
}

uint32_t MHRSA_GenKey(MH_RSA_KEY *pKeySrc, MH_RSA_KEY_SPACE *pKeyBase,
                     uint8_t *pu8Base, uint32_t u32GenKeyType) {
    mh_bn e;
    mh_bn p;
    mh_bn q;
    mh_bn n;
    mh_bn d;
    mh_bn dp;
    mh_bn dq;
    mh_bn qi;
    int nbytes = 0;
    int half = 0;
    int tries;
    uint32_t status;
    uint8_t ebuf[4] = {0x00, 0x01, 0x00, 0x01};
    if (sizeof(rsa_slot) > sizeof(MH_RSA_KEY_SPACE)) {
        return MH_RET_RSA_ERR;
    }
    if (!pKeySrc || !pKeyBase || !IS_RSA_GENKEY_TYPE(u32GenKeyType)) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (widths(pKeySrc->u32NBits, &nbytes, &half) != 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (u32GenKeyType == MH_RSA_GENKEY_EFC) {
        int elen;
        if (!pKeySrc->pu8E || pKeySrc->u32EBits < 2) {
            return MH_RET_RSA_PARAM_ERR;
        }
        elen = (int)((pKeySrc->u32EBits + 7u) / 8u);
        if (read_fixed(&e, pKeySrc->pu8E, elen) != 0 || mh_bn_is_zero(&e)) {
            return MH_RET_RSA_PARAM_ERR;
        }
    } else {
        pKeySrc->u32EBits = 32;
        if (mh_bn_from_be(&e, ebuf, 4) != 0) {
            return MH_RET_RSA_ERR;
        }
        if (pKeySrc->pu8E) {
            memcpy(pKeySrc->pu8E, ebuf, 4);
        }
    }
    for (tries = 0; tries < 32; tries++) {
        int generated;
        generated = gen_prime(&p, (int)(pKeySrc->u32NBits / 2u));
        if (generated == -2) {
            return MH_RET_RSA_TRNG_ERR;
        }
        if (generated != 0) {
            return MH_RET_RSA_PRIME_NOT_ACCEPTABLE;
        }
        generated = gen_prime(&q, (int)(pKeySrc->u32NBits / 2u));
        if (generated == -2) {
            return MH_RET_RSA_TRNG_ERR;
        }
        if (generated != 0) {
            return MH_RET_RSA_PRIME_NOT_ACCEPTABLE;
        }
        if (mh_bn_cmp(&p, &q) == 0 || mh_bn_mul(&n, &p, &q) != 0) {
            continue;
        }
        if (mh_bn_bitlen(&n) != (int)pKeySrc->u32NBits) {
            continue;
        }
        status = fill_private(&d, &dp, &dq, &qi, &e, &p, &q, 0);
        if (status == MH_RET_RSA_GCD_ISNOT_ONE) {
            continue;
        }
        if (status != MH_RET_RSA_SUCCESS) {
            return status;
        }
        publish(pKeySrc, nbytes, half, &n, &e, &d, &p, &q, &dp, &dq, &qi);
        return install(pKeySrc, pKeyBase, pu8Base, &n, &e, &d, &p, &q, &dp, &dq, &qi);
    }
    return MH_RET_RSA_PRIME_NOT_ACCEPTABLE;
}

uint32_t MHRSA_Pub(MH_RSA_CALL *pCall) {
    rsa_slot slot;
    mh_bn e;
    uint32_t status = ready(pCall, &slot);
    if (status != MH_RET_RSA_SUCCESS) {
        return status;
    }
    if (load_part(&e, &slot, PART_E) != 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    return exponentiate(pCall, &e);
}

uint32_t MHRSA_Pri(MH_RSA_CALL *pCall) {
    rsa_slot slot;
    mh_bn d;
    uint32_t status = ready(pCall, &slot);
    if (status != MH_RET_RSA_SUCCESS) {
        return status;
    }
    if ((slot.flags & FLAG_D) == 0 || load_part(&d, &slot, PART_D) != 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    return exponentiate(pCall, &d);
}

uint32_t MHRSA_CrtPri(MH_RSA_CALL *pCall) {
    rsa_slot slot;
    mh_bn p;
    mh_bn q;
    mh_bn dp;
    mh_bn dq;
    mh_bn qi;
    mh_bn c;
    mh_bn m1;
    mh_bn m2;
    mh_bn m2modp;
    mh_bn h;
    mh_bn diff;
    mh_bn prod;
    mh_bn m;
    uint8_t raw[512];
    uint32_t status;
    int written;
    status = ready(pCall, &slot);
    if (status != MH_RET_RSA_SUCCESS) {
        return status;
    }
    if ((slot.flags & FLAG_CRT) == 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (load_part(&p, &slot, PART_P) != 0 || load_part(&q, &slot, PART_Q) != 0 ||
        load_part(&dp, &slot, PART_DP) != 0 || load_part(&dq, &slot, PART_DQ) != 0 ||
        load_part(&qi, &slot, PART_QI) != 0 ||
        mh_bn_from_be(&c, pCall->pu8Input, (int)pCall->u32InLen) != 0) {
        return MH_RET_RSA_PARAM_ERR;
    }
    if (mh_bn_modexp_bn(&m1, &c, &dp, &p) != 0 || mh_bn_modexp_bn(&m2, &c, &dq, &q) != 0) {
        return MH_RET_RSA_ERR;
    }
    if (mh_bn_mod(&m2modp, &m2, &p) != 0) {
        return MH_RET_RSA_ERR;
    }
    if (mh_bn_cmp(&m1, &m2modp) >= 0) {
        if (mh_bn_sub(&diff, &m1, &m2modp) != 0) {
            return MH_RET_RSA_ERR;
        }
    } else if (mh_bn_sub(&diff, &m2modp, &m1) != 0 || mh_bn_sub(&diff, &p, &diff) != 0) {
        return MH_RET_RSA_ERR;
    }
    if (mh_bn_mul(&prod, &diff, &qi) != 0 || mh_bn_mod(&h, &prod, &p) != 0) {
        return MH_RET_RSA_ERR;
    }
    if (mh_bn_mul(&prod, &h, &q) != 0) {
        return MH_RET_RSA_ERR;
    }
    {
        uint64_t carry = 0;
        int i;
        int n = m2.n > prod.n ? m2.n : prod.n;
        memset(&m, 0, sizeof(m));
        for (i = 0; i < n; i++) {
            uint64_t v = carry;
            if (i < m2.n) {
                v += m2.d[i];
            }
            if (i < prod.n) {
                v += prod.d[i];
            }
            m.d[i] = (uint32_t)v;
            carry = v >> 32;
        }
        m.n = n;
        if (carry) {
            if (m.n >= MH_BN_MAX) {
                return MH_RET_RSA_ERR;
            }
            m.d[m.n++] = (uint32_t)carry;
        }
        while (m.n > 0 && m.d[m.n - 1] == 0) {
            m.n--;
        }
    }
    written = mh_bn_to_be(&m, raw, (int)slot.nbytes);
    if (written != 0) {
        return MH_RET_RSA_ERR;
    }
    memcpy(pCall->pu8Output, raw, slot.nbytes);
    pCall->u32OutLen = slot.nbytes;
    return MH_RET_RSA_SUCCESS;
}
