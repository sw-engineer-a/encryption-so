package com.mh1721.cryptoapp;

import java.nio.charset.StandardCharsets;

/** Modulus, exponents, and message taken from the screen. */
final class KeyMaterial {
    final byte[] modulus;
    final byte[] publicExponent;
    final byte[] privateExponent;
    final String message;
    final byte[] messageBytes;

    private KeyMaterial(byte[] modulus, byte[] publicExponent, byte[] privateExponent,
                        String message, byte[] messageBytes) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.message = message;
        this.messageBytes = messageBytes;
    }

    static KeyMaterial parse(String modulusHex, String publicHex, String privateHex, String messageText) {
        byte[] modulus = Hex.parse("modulus", modulusHex);
        byte[] publicExponent = Hex.parse("public exponent", publicHex);
        byte[] privateExponent = Hex.parse("private exponent", privateHex);
        if (modulus.length < 64 || modulus.length > 512) {
            throw new IllegalArgumentException(
                    "Modulus is " + modulus.length + " bytes; expected 64 to 512.");
        }
        String message = messageText == null ? "" : messageText;
        if (message.isEmpty()) {
            throw new IllegalArgumentException("Enter a message.");
        }
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        int max = modulus.length - 11;
        if (messageBytes.length > max) {
            throw new IllegalArgumentException(
                    "Message is " + messageBytes.length + " bytes; this key can encrypt at most " + max + ".");
        }
        return new KeyMaterial(modulus, publicExponent, privateExponent, message, messageBytes);
    }
}
