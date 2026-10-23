package com.mh1721.cryptoapp;

import com.mh1721.crypto.Mh1721Crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Reads the chip public key, encrypts and verifies with libmh1721crypto.so,
 * and asks the chip to decrypt and sign.
 */
public final class ChipSession {
    private static final String MESSAGE = "hello from the android app";

    private ChipSession() {
    }

    public static String exchange(UsbChipLink link) throws IOException {
        byte[] publicKey = link.transact(Mh1721Protocol.request(Mh1721Protocol.GET_PUBLIC_KEY, null));
        Mh1721Protocol.PublicNumbers numbers = Mh1721Protocol.parsePublicKey(publicKey);
        byte[] plain = MESSAGE.getBytes(StandardCharsets.UTF_8);
        byte[] cipher = Mh1721Crypto.encrypt(numbers.modulus, numbers.exponent, plain);
        if (cipher == null) {
            return "the software library rejected the chip public key";
        }

        byte[] opened = link.transact(Mh1721Protocol.request(Mh1721Protocol.DECRYPT, cipher));
        byte[] signature = link.transact(Mh1721Protocol.request(Mh1721Protocol.SIGN, plain));
        boolean verified = Mh1721Crypto.verify(numbers.modulus, numbers.exponent, plain, signature);
        String openedText = new String(opened, StandardCharsets.UTF_8);

        return "library: " + Mh1721Crypto.version()
                + "\nmodulus bytes: " + numbers.modulus.length
                + "\npublic exponent: " + hex(numbers.exponent)
                + "\nmessage: " + MESSAGE
                + "\nopened: " + openedText
                + "\nopened matches: " + Arrays.equals(plain, opened)
                + "\nverify: " + verified
                + "\ncipher bytes: " + cipher.length;
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            text.append(String.format("%02x", value & 0xff));
        }
        return text.toString();
    }
}
