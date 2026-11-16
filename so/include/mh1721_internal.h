#ifndef MH1721_INTERNAL_H
#define MH1721_INTERNAL_H

#include <stdint.h>

#define MH_BN_MAX 128

typedef struct {
    uint32_t d[MH_BN_MAX];
    int n;
} mh_bn;

int mh_bn_from_be(mh_bn *out, const uint8_t *bytes, int len);
int mh_bn_to_be(const mh_bn *a, uint8_t *out, int len);
int mh_bn_bytes(const mh_bn *a);
int mh_bn_bitlen(const mh_bn *a);
int mh_bn_cmp(const mh_bn *a, const mh_bn *b);
int mh_bn_is_zero(const mh_bn *a);
void mh_bn_set_u32(mh_bn *a, uint32_t v);
void mh_bn_copy(mh_bn *dst, const mh_bn *src);
int mh_bn_add_u32(mh_bn *a, uint32_t v);
int mh_bn_sub(mh_bn *r, const mh_bn *a, const mh_bn *b);
int mh_bn_mul(mh_bn *r, const mh_bn *a, const mh_bn *b);
void mh_bn_shr1(mh_bn *a);
int mh_bn_mod(mh_bn *r, const mh_bn *a, const mh_bn *m);
int mh_bn_divmod(mh_bn *q, mh_bn *r, const mh_bn *a, const mh_bn *m);
int mh_bn_modinv(mh_bn *r, const mh_bn *a, const mh_bn *m);
int mh_bn_gcd(mh_bn *r, const mh_bn *a, const mh_bn *b);
int mh_bn_modexp(const mh_bn *base, const mh_bn *exp, const mh_bn *mod, uint8_t *out, int out_len);
int mh_bn_modexp_bn(mh_bn *out, const mh_bn *base, const mh_bn *exp, const mh_bn *mod);

int mh_sha256(const uint8_t *in, int in_len, uint8_t out[32]);
int mh_random(uint8_t *buf, int len);

#endif
