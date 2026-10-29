package com.mh1721.cryptoapp;

import com.mh1721.crypto.Mh1721Crypto;

import java.io.IOException;
import java.util.Arrays;

/**
 * Runs the typed key through libmh1721crypto.so and through the MH1721,
 * then reports whether the two results match.
 *
 * The chip keeps its own private key. Signatures match when the typed
 * private exponent is that key. Both sides decrypt the ciphertext the
 * library produced, so those plaintexts can be compared too.
 */
public final class ChipSession {
    private ChipSession() {
    }

    public static String compare(UsbChipLink link, KeyMaterial keys) throws IOException {
        byte[] chipKey = link.transact(Mh1721Protocol.request(Mh1721Protocol.GET_PUBLIC_KEY, null));
        Mh1721Protocol.PublicNumbers chip = Mh1721Protocol.parsePublicKey(chipKey);
        byte[] chipModulus = stripLeadingZeros(chip.modulus);
        byte[] chipExponent = stripLeadingZeros(chip.exponent);

        byte[] appSignature = Mh1721Crypto.sign(keys.modulus, keys.privateExponent, keys.messageBytes);
        Attempt chipSignature = transact(link, Mh1721Protocol.SIGN, keys.messageBytes);
        boolean signaturesMatch = appSignature != null
                && chipSignature.bytes != null
                && Arrays.equals(appSignature, chipSignature.bytes);

        byte[] appCipher = Mh1721Crypto.encrypt(keys.modulus, keys.publicExponent, keys.messageBytes);
        byte[] appPlain = appCipher == null
                ? null
                : Mh1721Crypto.decrypt(keys.modulus, keys.privateExponent, appCipher);
        Attempt chipPlain = appCipher == null
                ? new Attempt(null, "app encryption failed, so the chip was not asked to decrypt")
                : transact(link, Mh1721Protocol.DECRYPT, appCipher);

        boolean appVerifiesChip = chipSignature.bytes != null && Mh1721Crypto.verify(
                keys.modulus, keys.publicExponent, keys.messageBytes, chipSignature.bytes);

        StringBuilder report = new StringBuilder();
        report.append("library: ").append(Mh1721Crypto.version());
        report.append("\nmodulus matches chip: ").append(Arrays.equals(keys.modulus, chipModulus));
        report.append("\npublic exponent matches chip: ").append(Arrays.equals(keys.publicExponent, chipExponent));
        report.append("\nmessage: ").append(keys.message);
        report.append("\n\nsignatures match: ").append(signaturesMatch);
        if (signaturesMatch) {
            report.append("\nsignature: ").append(Hex.format(appSignature));
        } else {
            report.append("\napp signature: ").append(Hex.format(appSignature));
            report.append("\nchip signature: ").append(showHex(chipSignature));
        }
        report.append("\n\napp opened: ").append(text(appPlain));
        report.append("\nchip opened: ").append(showText(chipPlain));
        report.append("\napp decrypt matches message: ").append(Arrays.equals(keys.messageBytes, appPlain));
        report.append("\nchip decrypt matches message: ").append(
                chipPlain.bytes != null && Arrays.equals(keys.messageBytes, chipPlain.bytes));
        report.append("\nplaintexts match: ").append(
                appPlain != null && chipPlain.bytes != null && Arrays.equals(appPlain, chipPlain.bytes));
        report.append("\napp verifies chip signature: ").append(appVerifiesChip);
        report.append("\n\nCiphertexts are not compared. PKCS#1 encryption padding is random.");
        return report.toString();
    }

    private static Attempt transact(UsbChipLink link, byte command, byte[] payload) {
        try {
            return new Attempt(link.transact(Mh1721Protocol.request(command, payload)), null);
        } catch (IOException error) {
            return new Attempt(null, error.getMessage());
        }
    }

    private static String showHex(Attempt attempt) {
        if (attempt.error != null) {
            return attempt.error;
        }
        return Hex.format(attempt.bytes);
    }

    private static String showText(Attempt attempt) {
        if (attempt.error != null) {
            return attempt.error;
        }
        return text(attempt.bytes);
    }

    private static String text(byte[] bytes) {
        if (bytes == null) {
            return "none";
        }
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static final class Attempt {
        final byte[] bytes;
        final String error;

        Attempt(byte[] bytes, String error) {
            this.bytes = bytes;
            this.error = error;
        }
    }

    private static byte[] stripLeadingZeros(byte[] value) {
        int start = 0;
        while (start < value.length - 1 && value[start] == 0) {
            start++;
        }
        if (start == 0) {
            return value;
        }
        byte[] trimmed = new byte[value.length - start];
        System.arraycopy(value, start, trimmed, 0, trimmed.length);
        return trimmed;
    }
}
