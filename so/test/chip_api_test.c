/* Host check for the MH1721 entry points in mh_rsa.h. */
#include "mh_rsa.h"
#include "mh1721_internal.h"

#include <stdio.h>
#include <string.h>

static int failed;

int mh_random(uint8_t *buf, int len) {
    static uint64_t state = 0x123456789abcdef0ull;
    int i;
    if (!buf || len <= 0) {
        return -1;
    }
    for (i = 0; i < len; i++) {
        uint64_t x = state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state = x;
        buf[i] = (uint8_t)((x * 0x2545f4914f6cdd1dull) >> 56);
    }
    return 0;
}

static void expect(const char *name, int ok) {
    if (!ok) {
        printf("FAIL %s\n", name);
        failed++;
    } else {
        printf("ok   %s\n", name);
    }
}

static void test_modinv(void) {
    mh_bn a;
    mh_bn m;
    mh_bn inv;
    mh_bn prod;
    mh_bn three;
    mh_bn_set_u32(&a, 3);
    mh_bn_set_u32(&m, 11);
    expect("modinv", mh_bn_modinv(&inv, &a, &m) == 0 && inv.n == 1 && inv.d[0] == 4);
    mh_bn_set_u32(&three, 3);
    expect("mul", mh_bn_mul(&prod, &three, &inv) == 0);
    expect("mod", mh_bn_mod(&prod, &prod, &m) == 0 && prod.n == 1 && prod.d[0] == 1);
}

static void test_roundtrip(void) {
    MH_RSA_KEY key;
    MH_RSA_KEY_SPACE space;
    MH_RSA_CALL call;
    uint8_t storage[MH_RSA_BASE_BYTES];
    uint8_t n[64], e[8], d[64], p[32], q[32], dp[32], dq[32], qi[32];
    uint8_t saved_d[64];
    uint8_t plain[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t cipher[64];
    uint8_t opened[64];
    uint8_t crt_opened[64];
    uint32_t rc;

    memset(&key, 0, sizeof(key));
    memset(n, 0, sizeof(n));
    memset(e, 0, sizeof(e));
    memset(d, 0, sizeof(d));
    memset(p, 0, sizeof(p));
    memset(q, 0, sizeof(q));
    memset(dp, 0, sizeof(dp));
    memset(dq, 0, sizeof(dq));
    memset(qi, 0, sizeof(qi));
    key.u32NBits = 512;
    key.pu8N = n;
    key.pu8E = e;
    key.pu8D = d;
    key.pu8P = p;
    key.pu8Q = q;
    key.pu8Dp = dp;
    key.pu8Dq = dq;
    key.pu8Qi = qi;

    rc = MHRSA_GenKey(&key, &space, storage, MH_RSA_GENKEY_GENE);
    expect("genkey", rc == MH_RET_RSA_SUCCESS);
    if (rc != MH_RET_RSA_SUCCESS) {
        printf("  genkey status %08x\n", rc);
        return;
    }
    memcpy(saved_d, d, sizeof(d));

    memset(&call, 0, sizeof(call));
    call.KeyBase = &space;
    call.pu8Input = plain;
    call.u32InLen = sizeof(plain);
    call.pu8Output = cipher;
    rc = MHRSA_Pub(&call);
    expect("pub", rc == MH_RET_RSA_SUCCESS && call.u32OutLen == 64);
    if (rc != MH_RET_RSA_SUCCESS) {
        return;
    }

    call.pu8Input = cipher;
    call.u32InLen = call.u32OutLen;
    call.pu8Output = opened;
    rc = MHRSA_Pri(&call);
    expect("pri", rc == MH_RET_RSA_SUCCESS);
    expect("pri matches", rc == MH_RET_RSA_SUCCESS &&
           memcmp(opened + 56, plain, sizeof(plain)) == 0 &&
           opened[0] == 0);

    call.pu8Output = crt_opened;
    rc = MHRSA_CrtPri(&call);
    expect("crt", rc == MH_RET_RSA_SUCCESS && memcmp(opened, crt_opened, 64) == 0);

    memset(d, 0, sizeof(d));
    rc = MHRSA_CompleteKey(&key, &space, storage, MH_RSA_COMPLETE_D);
    expect("complete d", rc == MH_RET_RSA_SUCCESS && memcmp(d, saved_d, sizeof(d)) == 0);

    call.pu8Input = n;
    call.u32InLen = 64;
    call.pu8Output = opened;
    rc = MHRSA_Pub(&call);
    expect("reject input >= n", rc == MH_RET_RSA_PARAM_ERR);
}

static void test_params(void) {
    expect("null pub", MHRSA_Pub(NULL) == MH_RET_RSA_PARAM_ERR);
    expect("null gen", MHRSA_GenKey(NULL, NULL, NULL, MH_RSA_GENKEY_GENE) == MH_RET_RSA_PARAM_ERR);
}

int main(void) {
    test_modinv();
    test_params();
    test_roundtrip();
    printf("%s\n", failed ? "FAILED" : "passed");
    return failed ? 1 : 0;
}
