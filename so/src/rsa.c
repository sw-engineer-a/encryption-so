#include "mh1721_crypto.h"
#include "mh1721_internal.h"

#include <string.h>

static const uint8_t SHA256_PREFIX[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) {
        *v++ = 0;
    }
}

static int load_key(mh_bn *mod, mh_bn *exp, const uint8_t *modulus, int modulus_len,
                    const uint8_t *exponent, int exponent_len, int *k) {
    if (!modulus || !exponent || modulus_len <= 0 || exponent_len <= 0) {
        return -1;
    }
    if (mh_bn_from_be(mod, modulus, modulus_len) != 0 ||
        mh_bn_from_be(exp, exponent, exponent_len) != 0) {
        return -1;
    }
    *k = mh_bn_bytes(mod);
    if (*k < 64 || *k > 512 || exp->n <= 0 || (mod->d[0] & 1u) == 0) {
        return -1;
    }
    return 0;
}

static int pow_mod(const mh_bn *exp, const mh_bn *mod, const uint8_t *block, int block_len,
                   uint8_t *out, int k) {
    mh_bn base;
    int n;
    if (block_len <= 0 || mh_bn_from_be(&base, block, block_len) != 0) {
        return -1;
    }
    n = mh_bn_modexp(&base, exp, mod, out, k);
    wipe(&base, sizeof(base));
    return n == k ? 0 : -1;
}

static int fill_nonzero(uint8_t *dst, int len) {
    int filled = 0;
    while (filled < len) {
        uint8_t draw[32];
        int i;
        if (mh_random(draw, (int)sizeof(draw)) != 0) {
            return -1;
        }
        for (i = 0; i < (int)sizeof(draw) && filled < len; i++) {
            if (draw[i] != 0) {
                dst[filled++] = draw[i];
            }
        }
    }
    return 0;
}

int mh1721_rsa_encrypt(const uint8_t *modulus, int modulus_len,
                       const uint8_t *exponent, int exponent_len,
                       const uint8_t *in, int in_len,
                       uint8_t *out, int out_cap) {
    mh_bn mod;
    mh_bn exp;
    uint8_t em[512];
    int k;
    int ps_len;
    int rc;

    if (!out || in_len < 0 || (in_len > 0 && !in)) {
        return -1;
    }
    if (load_key(&mod, &exp, modulus, modulus_len, exponent, exponent_len, &k) != 0) {
        return -1;
    }
    ps_len = k - in_len - 3;
    if (ps_len < 8 || out_cap < k) {
        return -1;
    }
    em[0] = 0x00;
    em[1] = 0x02;
    if (fill_nonzero(em + 2, ps_len) != 0) {
        wipe(em, sizeof(em));
        return -1;
    }
    em[2 + ps_len] = 0x00;
    if (in_len > 0) {
        memcpy(em + 3 + ps_len, in, (size_t)in_len);
    }
    rc = pow_mod(&exp, &mod, em, k, out, k);
    wipe(em, sizeof(em));
    wipe(&exp, sizeof(exp));
    return rc == 0 ? k : -1;
}

int mh1721_rsa_decrypt(const uint8_t *modulus, int modulus_len,
                       const uint8_t *exponent, int exponent_len,
                       const uint8_t *in, int in_len,
                       uint8_t *out, int out_cap) {
    mh_bn mod;
    mh_bn exp;
    uint8_t em[512];
    int k;
    int i;
    int msg_len;

    if (!in || !out || in_len <= 0) {
        return -1;
    }
    if (load_key(&mod, &exp, modulus, modulus_len, exponent, exponent_len, &k) != 0) {
        return -1;
    }
    if (pow_mod(&exp, &mod, in, in_len, em, k) != 0) {
        wipe(&exp, sizeof(exp));
        return -1;
    }
    if (em[0] != 0x00 || em[1] != 0x02) {
        wipe(em, sizeof(em));
        wipe(&exp, sizeof(exp));
        return -1;
    }
    i = 2;
    while (i < k && em[i] != 0) {
        i++;
    }
    if (i < 10 || i >= k) {
        wipe(em, sizeof(em));
        wipe(&exp, sizeof(exp));
        return -1;
    }
    msg_len = k - (i + 1);
    if (out_cap < msg_len) {
        wipe(em, sizeof(em));
        wipe(&exp, sizeof(exp));
        return -1;
    }
    if (msg_len > 0) {
        memcpy(out, em + i + 1, (size_t)msg_len);
    }
    wipe(em, sizeof(em));
    wipe(&exp, sizeof(exp));
    return msg_len;
}

static int sign_em(const uint8_t *in, int in_len, int k, uint8_t em[512]) {
    uint8_t hash[32];
    int tlen = (int)sizeof(SHA256_PREFIX) + 32;
    int ps_len = k - tlen - 3;
    if (ps_len < 8) {
        return -1;
    }
    if (mh_sha256(in, in_len, hash) != 0) {
        return -1;
    }
    em[0] = 0x00;
    em[1] = 0x01;
    memset(em + 2, 0xff, (size_t)ps_len);
    em[2 + ps_len] = 0x00;
    memcpy(em + 3 + ps_len, SHA256_PREFIX, sizeof(SHA256_PREFIX));
    memcpy(em + 3 + ps_len + sizeof(SHA256_PREFIX), hash, 32);
    return 0;
}

int mh1721_rsa_sign(const uint8_t *modulus, int modulus_len,
                    const uint8_t *exponent, int exponent_len,
                    const uint8_t *in, int in_len,
                    uint8_t *out, int out_cap) {
    mh_bn mod;
    mh_bn exp;
    uint8_t em[512];
    int k;
    int rc;

    if (!out || in_len < 0 || (in_len > 0 && !in)) {
        return -1;
    }
    if (load_key(&mod, &exp, modulus, modulus_len, exponent, exponent_len, &k) != 0) {
        return -1;
    }
    if (out_cap < k || sign_em(in, in_len, k, em) != 0) {
        wipe(&exp, sizeof(exp));
        return -1;
    }
    rc = pow_mod(&exp, &mod, em, k, out, k);
    wipe(em, sizeof(em));
    wipe(&exp, sizeof(exp));
    return rc == 0 ? k : -1;
}

int mh1721_rsa_verify(const uint8_t *modulus, int modulus_len,
                      const uint8_t *exponent, int exponent_len,
                      const uint8_t *in, int in_len,
                      const uint8_t *signature, int signature_len) {
    mh_bn mod;
    mh_bn exp;
    uint8_t em[512];
    uint8_t got[512];
    int k;
    int rc = -1;

    if (in_len < 0 || (in_len > 0 && !in) || !signature || signature_len <= 0) {
        return -1;
    }
    if (load_key(&mod, &exp, modulus, modulus_len, exponent, exponent_len, &k) != 0) {
        return -1;
    }
    if (sign_em(in, in_len, k, em) == 0 &&
        pow_mod(&exp, &mod, signature, signature_len, got, k) == 0 &&
        memcmp(em, got, (size_t)k) == 0) {
        rc = 0;
    }
    wipe(em, sizeof(em));
    wipe(got, sizeof(got));
    return rc;
}

const char *mh1721_version(void) {
    return "2.0.0";
}
