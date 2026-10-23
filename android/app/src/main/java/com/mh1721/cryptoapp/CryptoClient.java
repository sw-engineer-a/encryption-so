package com.mh1721.cryptoapp;

import com.mh1721.crypto.Mh1721Crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Calls libmh1721crypto.so through Mh1721Crypto.
 * The .so is loaded by Mh1721Crypto's static initializer.
 */
public final class CryptoClient {
    private final byte[] modulus;
    private final byte[] publicExponent;
    private final byte[] privateExponent;

    public CryptoClient(byte[] x509Public, byte[] pkcs8Private) throws Exception {
        RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(x509Public));
        RSAPrivateKey priv = (RSAPrivateKey) KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8Private));
        this.modulus = unsigned(pub.getModulus());
        this.publicExponent = unsigned(pub.getPublicExponent());
        this.privateExponent = unsigned(priv.getPrivateExponent());
    }

    public byte[] seal(String message) {
        return Mh1721Crypto.encrypt(modulus, publicExponent, message.getBytes(StandardCharsets.UTF_8));
    }

    public String open(byte[] cipher) {
        byte[] plain = Mh1721Crypto.decrypt(modulus, privateExponent, cipher);
        if (plain == null) {
            return null;
        }
        return new String(plain, StandardCharsets.UTF_8);
    }

    public byte[] sign(String message) {
        return Mh1721Crypto.sign(modulus, privateExponent, message.getBytes(StandardCharsets.UTF_8));
    }

    public boolean verify(String message, byte[] signature) {
        return Mh1721Crypto.verify(
                modulus, publicExponent, message.getBytes(StandardCharsets.UTF_8), signature);
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            byte[] trimmed = new byte[raw.length - 1];
            System.arraycopy(raw, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return raw;
    }
}
