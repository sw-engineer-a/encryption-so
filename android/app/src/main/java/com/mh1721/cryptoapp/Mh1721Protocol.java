package com.mh1721.cryptoapp;

import java.io.IOException;

/**
 * Host frames for the MH1721 demo. The firmware on the chip must use this
 * layout. Megahunt does not publish a command set for the chip.
 *
 * Both directions start with one command or status byte, then a 16-bit
 * big-endian length, then that many payload bytes. Status 0 means success.
 *
 * GET_PUBLIC_KEY (0x01), empty request.
 * Response payload: uint16 modulus length, modulus, uint16 exponent length, exponent.
 *
 * DECRYPT (0x02), request payload is the ciphertext. Response is the plaintext.
 * SIGN (0x03), request payload is the message. Response is the signature.
 *
 * The private exponent stays on the chip. The phone only receives the public numbers.
 */
public final class Mh1721Protocol {
    public static final byte GET_PUBLIC_KEY = 0x01;
    public static final byte DECRYPT = 0x02;
    public static final byte SIGN = 0x03;

    private Mh1721Protocol() {
    }

    public static byte[] request(byte command, byte[] payload) {
        int length = payload == null ? 0 : payload.length;
        if (length > 0xffff) {
            throw new IllegalArgumentException("payload longer than 65535 bytes");
        }
        byte[] frame = new byte[3 + length];
        frame[0] = command;
        frame[1] = (byte) (length >> 8);
        frame[2] = (byte) length;
        if (length > 0) {
            System.arraycopy(payload, 0, frame, 3, length);
        }
        return frame;
    }

    public static PublicNumbers parsePublicKey(byte[] payload) throws IOException {
        if (payload == null || payload.length < 4) {
            throw new IOException("public key response is too short");
        }
        int offset = 0;
        int modulusLength = readLength(payload, offset);
        offset += 2;
        byte[] modulus = readBlock(payload, offset, modulusLength, "modulus");
        offset += modulusLength;
        int exponentLength = readLength(payload, offset);
        offset += 2;
        byte[] exponent = readBlock(payload, offset, exponentLength, "public exponent");
        offset += exponentLength;
        if (offset != payload.length) {
            throw new IOException("public key response has " + (payload.length - offset) + " extra bytes");
        }
        if (modulusLength < 64 || modulusLength > 512) {
            throw new IOException("modulus is " + modulusLength + " bytes; expected 64 to 512");
        }
        return new PublicNumbers(modulus, exponent);
    }

    private static int readLength(byte[] payload, int offset) throws IOException {
        if (offset + 2 > payload.length) {
            throw new IOException("public key response ended during a length");
        }
        return ((payload[offset] & 0xff) << 8) | (payload[offset + 1] & 0xff);
    }

    private static byte[] readBlock(byte[] payload, int offset, int length, String name) throws IOException {
        if (length <= 0 || offset + length > payload.length) {
            throw new IOException(name + " length " + length + " does not fit the response");
        }
        byte[] block = new byte[length];
        System.arraycopy(payload, offset, block, 0, length);
        return block;
    }

    public static final class PublicNumbers {
        public final byte[] modulus;
        public final byte[] exponent;

        public PublicNumbers(byte[] modulus, byte[] exponent) {
            this.modulus = modulus;
            this.exponent = exponent;
        }
    }
}
