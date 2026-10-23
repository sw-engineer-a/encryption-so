#include "mh1721_internal.h"

#include <string.h>

int mh_bn_from_be(mh_bn *out, const uint8_t *bytes, int len) {
    int i;
    if (!out || len < 0 || (len > 0 && !bytes)) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    while (len > 0 && bytes[0] == 0) {
        bytes++;
        len--;
    }
    if (len == 0) {
        return 0;
    }
    out->n = (len + 3) / 4;
    if (out->n > MH_BN_MAX) {
        return -1;
    }
    for (i = 0; i < len; i++) {
        int bit = (len - 1 - i) * 8;
        out->d[bit / 32] |= (uint32_t)bytes[i] << (bit % 32);
    }
    while (out->n > 0 && out->d[out->n - 1] == 0) {
        out->n--;
    }
    return 0;
}

int mh_bn_bytes(const mh_bn *a) {
    uint32_t top;
    int extra;
    if (!a || a->n <= 0) {
        return 0;
    }
    top = a->d[a->n - 1];
    if (top < 0x100u) {
        extra = 1;
    } else if (top < 0x10000u) {
        extra = 2;
    } else if (top < 0x1000000u) {
        extra = 3;
    } else {
        extra = 4;
    }
    return (a->n - 1) * 4 + extra;
}

static int cmp_limbs(const uint32_t *a, int an, const uint32_t *b, int bn) {
    int i;
    if (an != bn) {
        return an > bn ? 1 : -1;
    }
    for (i = an - 1; i >= 0; i--) {
        if (a[i] != b[i]) {
            return a[i] > b[i] ? 1 : -1;
        }
    }
    return 0;
}

static void sub_limbs(uint32_t *a, const uint32_t *b, int k) {
    uint32_t borrow = 0;
    int i;
    for (i = 0; i < k; i++) {
        uint64_t v = (uint64_t)a[i] - (uint64_t)(b ? b[i] : 0) - borrow;
        a[i] = (uint32_t)v;
        borrow = (v >> 63) & 1u;
    }
}

static uint32_t inv32(uint32_t n0) {
    uint32_t inv = 1;
    int i;
    for (i = 0; i < 5; i++) {
        inv = inv * (2u - n0 * inv);
    }
    return 0u - inv;
}

static void cios(uint32_t *r, const uint32_t *a, const uint32_t *b,
                 const uint32_t *n, int k, uint32_t n0inv) {
    uint32_t t[MH_BN_MAX + 2];
    int i;
    int j;
    memset(t, 0, (size_t)(k + 2) * sizeof(uint32_t));
    for (i = 0; i < k; i++) {
        uint64_t c = 0;
        uint32_t m;
        for (j = 0; j < k; j++) {
            c += (uint64_t)t[j] + (uint64_t)a[j] * b[i];
            t[j] = (uint32_t)c;
            c >>= 32;
        }
        c += t[k];
        t[k] = (uint32_t)c;
        t[k + 1] = (uint32_t)(c >> 32);

        m = t[0] * n0inv;
        c = (uint64_t)t[0] + (uint64_t)m * n[0];
        c >>= 32;
        for (j = 1; j < k; j++) {
            c += (uint64_t)t[j] + (uint64_t)m * n[j];
            t[j - 1] = (uint32_t)c;
            c >>= 32;
        }
        c += t[k];
        t[k - 1] = (uint32_t)c;
        c >>= 32;
        t[k] = t[k + 1] + (uint32_t)c;
        t[k + 1] = 0;
    }
    memcpy(r, t, (size_t)k * sizeof(uint32_t));
    if (t[k] || cmp_limbs(r, k, n, k) >= 0) {
        sub_limbs(r, n, k);
    }
    memset(t, 0, sizeof(t));
}

static void r_squared(uint32_t *out, const uint32_t *n, int k) {
    uint32_t x[MH_BN_MAX + 1];
    int xn = 1;
    int step;
    memset(x, 0, sizeof(x));
    x[0] = 1;
    for (step = 0; step < 64 * k; step++) {
        uint32_t wide[MH_BN_MAX + 2];
        uint32_t carry = 0;
        int j;
        int wn;
        memset(wide, 0, sizeof(wide));
        for (j = 0; j < xn; j++) {
            uint64_t v = (uint64_t)x[j] * 2u + carry;
            wide[j] = (uint32_t)v;
            carry = (uint32_t)(v >> 32);
        }
        wn = xn;
        if (carry) {
            wide[xn] = carry;
            wn = xn + 1;
        }
        if (cmp_limbs(wide, wn, n, k) >= 0) {
            sub_limbs(wide, n, wn > k ? wn : k);
            wn = k;
            while (wn > 0 && wide[wn - 1] == 0) {
                wn--;
            }
        }
        memset(x, 0, sizeof(x));
        memcpy(x, wide, (size_t)wn * sizeof(uint32_t));
        xn = wn;
    }
    memset(out, 0, (size_t)k * sizeof(uint32_t));
    memcpy(out, x, (size_t)k * sizeof(uint32_t));
}

static void store_be(const uint32_t *d, int k_bytes, uint8_t *out) {
    int i;
    for (i = 0; i < k_bytes; i++) {
        int from_right = (k_bytes - 1 - i) * 8;
        out[i] = (uint8_t)((d[from_right / 32] >> (from_right % 32)) & 0xff);
    }
}

int mh_bn_modexp(const mh_bn *base, const mh_bn *exp, const mh_bn *mod, uint8_t *out, int out_len) {
    uint32_t r2[MH_BN_MAX];
    uint32_t one[MH_BN_MAX];
    uint32_t b[MH_BN_MAX];
    uint32_t a[MH_BN_MAX];
    uint32_t x[MH_BN_MAX];
    uint32_t n0inv;
    int k;
    int bits;
    int i;
    int nbytes;

    if (!base || !exp || !mod || !out || mod->n <= 0 || (mod->d[0] & 1u) == 0) {
        return -1;
    }
    if (cmp_limbs(base->d, base->n, mod->d, mod->n) >= 0) {
        return -1;
    }
    k = mod->n;
    nbytes = mh_bn_bytes(mod);
    if (nbytes <= 0 || out_len < nbytes) {
        return -1;
    }
    n0inv = inv32(mod->d[0]);
    r_squared(r2, mod->d, k);
    memset(one, 0, sizeof(one));
    one[0] = 1;
    memset(b, 0, sizeof(b));
    if (base->n > 0) {
        memcpy(b, base->d, (size_t)base->n * sizeof(uint32_t));
    }
    cios(a, one, r2, mod->d, k, n0inv);
    cios(x, b, r2, mod->d, k, n0inv);

    bits = exp->n * 32;
    while (bits > 0) {
        uint32_t limb = exp->d[(bits - 1) >> 5];
        if ((limb >> ((bits - 1) & 31)) & 1u) {
            break;
        }
        bits--;
    }
    for (i = bits - 1; i >= 0; i--) {
        uint32_t sq[MH_BN_MAX];
        cios(sq, a, a, mod->d, k, n0inv);
        memcpy(a, sq, (size_t)k * sizeof(uint32_t));
        if ((exp->d[i >> 5] >> (i & 31)) & 1u) {
            uint32_t mul[MH_BN_MAX];
            cios(mul, a, x, mod->d, k, n0inv);
            memcpy(a, mul, (size_t)k * sizeof(uint32_t));
        }
    }
    cios(x, a, one, mod->d, k, n0inv);
    store_be(x, nbytes, out);
    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));
    memset(x, 0, sizeof(x));
    return nbytes;
}
