#ifndef MH1721_INTERNAL_H
#define MH1721_INTERNAL_H

#include <stdint.h>

#define MH_BN_MAX 128

typedef struct {
    uint32_t d[MH_BN_MAX];
    int n;
} mh_bn;

int mh_bn_from_be(mh_bn *out, const uint8_t *bytes, int len);
int mh_bn_bytes(const mh_bn *a);
int mh_bn_modexp(const mh_bn *base, const mh_bn *exp, const mh_bn *mod, uint8_t *out, int out_len);

int mh_sha256(const uint8_t *in, int in_len, uint8_t out[32]);
int mh_random(uint8_t *buf, int len);

#endif
