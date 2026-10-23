package com.mh1721.crypto;

/**
 * Loads libmh1721crypto.so. The android app compiles this file in place.
 * Keep the package name com.mh1721.crypto so the JNI names still match.
 *
 * The built library is packed from:
 *   so/dist/jniLibs/arm64-v8a/libmh1721crypto.so
 *   so/dist/jniLibs/armeabi-v7a/libmh1721crypto.so
 *   so/dist/jniLibs/x86_64/libmh1721crypto.so
 *
 * Modulus and exponents are unsigned big-endian. A leading 0x00 from
 * BigInteger.toByteArray() is accepted.
 */
public final class Mh1721Crypto {
    static {
        System.loadLibrary("mh1721crypto");
    }

    private Mh1721Crypto() {
    }

    public static native String version();

    /** PKCS#1 v1.5 encryption. data must be at most modulusBytes - 11. */
    public static native byte[] encrypt(byte[] modulus, byte[] publicExponent, byte[] data);

    /** PKCS#1 v1.5 decryption. */
    public static native byte[] decrypt(byte[] modulus, byte[] privateExponent, byte[] data);

    /** SHA-256 signature with PKCS#1 v1.5 type-1 padding. */
    public static native byte[] sign(byte[] modulus, byte[] privateExponent, byte[] data);

    /** Returns true when the SHA-256 PKCS#1 v1.5 signature matches data. */
    public static native boolean verify(byte[] modulus, byte[] publicExponent, byte[] data, byte[] signature);
}
