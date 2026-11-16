#include "mh1721_internal.h"

#include <string.h>

static void trim(mh_bn *a) {
    while (a->n > 0 && a->d[a->n - 1] == 0) {
        a->n--;
    }
}

int mh_bn_to_be(const mh_bn *a, uint8_t *out, int len) {
    int need;
    int i;
    if (!a || !out || len < 0) {
        return -1;
    }
    need = mh_bn_bytes(a);
    if (need > len) {
        return -1;
    }
    memset(out, 0, (size_t)len);
    for (i = 0; i < need; i++) {
        int from_right = (need - 1 - i) * 8;
        out[len - need + i] = (uint8_t)((a->d[from_right / 32] >> (from_right % 32)) & 0xff);
    }
    return 0;
}

int mh_bn_bitlen(const mh_bn *a) {
    uint32_t top;
    int bits;
    if (!a || a->n <= 0) {
        return 0;
    }
    top = a->d[a->n - 1];
    bits = (a->n - 1) * 32;
    while (top) {
        bits++;
        top >>= 1;
    }
    return bits;
}

int mh_bn_cmp(const mh_bn *a, const mh_bn *b) {
    int an;
    int bn;
    int i;
    if (!a || !b) {
        return 0;
    }
    an = a->n;
    bn = b->n;
    if (an != bn) {
        return an > bn ? 1 : -1;
    }
    for (i = an - 1; i >= 0; i--) {
        if (a->d[i] != b->d[i]) {
            return a->d[i] > b->d[i] ? 1 : -1;
        }
    }
    return 0;
}

int mh_bn_is_zero(const mh_bn *a) {
    return !a || a->n <= 0;
}

void mh_bn_set_u32(mh_bn *a, uint32_t v) {
    memset(a, 0, sizeof(*a));
    if (v) {
        a->d[0] = v;
        a->n = 1;
    }
}

void mh_bn_copy(mh_bn *dst, const mh_bn *src) {
    if (dst == src) {
        return;
    }
    memset(dst, 0, sizeof(*dst));
    dst->n = src->n;
    if (src->n > 0) {
        memcpy(dst->d, src->d, (size_t)src->n * sizeof(uint32_t));
    }
}

int mh_bn_add_u32(mh_bn *a, uint32_t v) {
    uint64_t carry = v;
    int i;
    if (!a) {
        return -1;
    }
    if (a->n == 0) {
        a->n = 1;
        a->d[0] = 0;
    }
    for (i = 0; i < a->n && carry; i++) {
        carry += a->d[i];
        a->d[i] = (uint32_t)carry;
        carry >>= 32;
    }
    if (carry) {
        if (a->n >= MH_BN_MAX) {
            return -1;
        }
        a->d[a->n++] = (uint32_t)carry;
    }
    trim(a);
    return 0;
}

int mh_bn_sub(mh_bn *r, const mh_bn *a, const mh_bn *b) {
    uint32_t borrow = 0;
    int n;
    int i;
    mh_bn tmp;
    if (!r || !a || !b || mh_bn_cmp(a, b) < 0) {
        return -1;
    }
    n = a->n > b->n ? a->n : b->n;
    memset(&tmp, 0, sizeof(tmp));
    for (i = 0; i < n; i++) {
        uint64_t av = i < a->n ? a->d[i] : 0;
        uint64_t bv = i < b->n ? b->d[i] : 0;
        uint64_t v = av - bv - borrow;
        tmp.d[i] = (uint32_t)v;
        borrow = (uint32_t)((v >> 63) & 1u);
    }
    tmp.n = n;
    trim(&tmp);
    mh_bn_copy(r, &tmp);
    return 0;
}

int mh_bn_mul(mh_bn *r, const mh_bn *a, const mh_bn *b) {
    uint32_t tmp[MH_BN_MAX];
    int i;
    int j;
    if (!r || !a || !b) {
        return -1;
    }
    if (a->n <= 0 || b->n <= 0) {
        mh_bn_set_u32(r, 0);
        return 0;
    }
    if (a->n + b->n > MH_BN_MAX) {
        return -1;
    }
    memset(tmp, 0, sizeof(tmp));
    for (i = 0; i < a->n; i++) {
        uint64_t carry = 0;
        for (j = 0; j < b->n; j++) {
            uint64_t c = (uint64_t)tmp[i + j] + (uint64_t)a->d[i] * b->d[j] + carry;
            tmp[i + j] = (uint32_t)c;
            carry = c >> 32;
        }
        j = i + b->n;
        while (carry) {
            uint64_t c;
            if (j >= MH_BN_MAX) {
                return -1;
            }
            c = (uint64_t)tmp[j] + carry;
            tmp[j] = (uint32_t)c;
            carry = c >> 32;
            j++;
        }
    }
    memset(r, 0, sizeof(*r));
    r->n = a->n + b->n;
    if (r->n > MH_BN_MAX) {
        r->n = MH_BN_MAX;
    }
    memcpy(r->d, tmp, (size_t)r->n * sizeof(uint32_t));
    trim(r);
    return 0;
}

void mh_bn_shr1(mh_bn *a) {
    uint32_t carry = 0;
    int i;
    if (!a || a->n <= 0) {
        return;
    }
    for (i = a->n - 1; i >= 0; i--) {
        uint32_t next = a->d[i] & 1u;
        a->d[i] = (a->d[i] >> 1) | (carry << 31);
        carry = next;
    }
    trim(a);
}

static int bit_at(const mh_bn *a, int i) {
    if (i < 0 || i >= a->n * 32) {
        return 0;
    }
    return (int)((a->d[i >> 5] >> (i & 31)) & 1u);
}

static int set_bit(mh_bn *a, int i) {
    int limb = i >> 5;
    if (i < 0 || limb >= MH_BN_MAX) {
        return -1;
    }
    while (a->n <= limb) {
        a->d[a->n++] = 0;
    }
    a->d[limb] |= 1u << (i & 31);
    return 0;
}

static int shl1(mh_bn *a) {
    uint32_t carry = 0;
    int i;
    for (i = 0; i < a->n; i++) {
        uint32_t next = a->d[i] >> 31;
        a->d[i] = (a->d[i] << 1) | carry;
        carry = next;
    }
    if (carry) {
        if (a->n >= MH_BN_MAX) {
            return -1;
        }
        a->d[a->n++] = carry;
    }
    return 0;
}

int mh_bn_divmod(mh_bn *q, mh_bn *rem, const mh_bn *a, const mh_bn *m) {
    mh_bn r;
    int bits;
    int i;
    if (!a || !m || mh_bn_is_zero(m)) {
        return -1;
    }
    memset(&r, 0, sizeof(r));
    if (q) {
        mh_bn_set_u32(q, 0);
    }
    bits = mh_bn_bitlen(a);
    for (i = bits - 1; i >= 0; i--) {
        if (shl1(&r) != 0) {
            return -1;
        }
        if (bit_at(a, i) && mh_bn_add_u32(&r, 1) != 0) {
            return -1;
        }
        if (mh_bn_cmp(&r, m) >= 0) {
            if (mh_bn_sub(&r, &r, m) != 0) {
                return -1;
            }
            if (q && set_bit(q, i) != 0) {
                return -1;
            }
        }
    }
    if (rem) {
        mh_bn_copy(rem, &r);
    }
    return 0;
}

int mh_bn_mod(mh_bn *r, const mh_bn *a, const mh_bn *m) {
    return mh_bn_divmod(NULL, r, a, m);
}

int mh_bn_modinv(mh_bn *out, const mh_bn *aa, const mh_bn *mm) {
    mh_bn r0;
    mh_bn r1;
    mh_bn s0;
    mh_bn s1;
    mh_bn q;
    mh_bn rem;
    mh_bn prod;
    mh_bn next;
    if (!out || !aa || !mm || mh_bn_is_zero(mm)) {
        return -1;
    }
    if (mh_bn_mod(&r0, aa, mm) != 0) {
        return -1;
    }
    mh_bn_copy(&r1, mm);
    mh_bn_set_u32(&s0, 1);
    mh_bn_set_u32(&s1, 0);
    if (mh_bn_is_zero(&r0)) {
        return -2;
    }
    while (!mh_bn_is_zero(&r1)) {
        if (mh_bn_divmod(&q, &rem, &r0, &r1) != 0) {
            return -1;
        }
        if (mh_bn_mul(&prod, &q, &s1) != 0 || mh_bn_mod(&prod, &prod, mm) != 0) {
            return -1;
        }
        if (mh_bn_cmp(&s0, &prod) >= 0) {
            if (mh_bn_sub(&next, &s0, &prod) != 0) {
                return -1;
            }
        } else {
            mh_bn diff;
            if (mh_bn_sub(&diff, &prod, &s0) != 0 || mh_bn_sub(&next, mm, &diff) != 0) {
                return -1;
            }
        }
        mh_bn_copy(&r0, &r1);
        mh_bn_copy(&r1, &rem);
        mh_bn_copy(&s0, &s1);
        mh_bn_copy(&s1, &next);
    }
    if (!(r0.n == 1 && r0.d[0] == 1)) {
        return -2;
    }
    mh_bn_copy(out, &s0);
    return 0;
}

int mh_bn_gcd(mh_bn *r, const mh_bn *a, const mh_bn *b) {
    mh_bn x;
    mh_bn y;
    if (!r || !a || !b) {
        return -1;
    }
    mh_bn_copy(&x, a);
    mh_bn_copy(&y, b);
    while (!mh_bn_is_zero(&y)) {
        mh_bn rem;
        if (mh_bn_mod(&rem, &x, &y) != 0) {
            return -1;
        }
        mh_bn_copy(&x, &y);
        mh_bn_copy(&y, &rem);
    }
    mh_bn_copy(r, &x);
    return 0;
}

int mh_bn_modexp_bn(mh_bn *out, const mh_bn *base, const mh_bn *exp, const mh_bn *mod) {
    mh_bn reduced;
    const mh_bn *use;
    uint8_t buf[512];
    int k;
    int n;
    if (!out || !base || !exp || !mod) {
        return -1;
    }
    if (mh_bn_cmp(base, mod) >= 0) {
        if (mh_bn_mod(&reduced, base, mod) != 0) {
            return -1;
        }
        use = &reduced;
    } else {
        use = base;
    }
    k = mh_bn_bytes(mod);
    if (k <= 0 || k > (int)sizeof(buf)) {
        return -1;
    }
    n = mh_bn_modexp(use, exp, mod, buf, k);
    if (n != k) {
        return -1;
    }
    return mh_bn_from_be(out, buf, n);
}
