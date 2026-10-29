package com.mh1721.cryptoapp;

/**
 * Hex for the modulus and exponents typed into the app.
 * Digits may contain spaces, colons, or a 0x prefix.
 */
final class Hex {
    private Hex() {
    }

    static byte[] parse(String label, String text) {
        if (text == null) {
            throw new IllegalArgumentException("Enter the " + label + " as hex.");
        }
        String cleaned = text.replace("0x", "").replace("0X", "");
        StringBuilder digits = new StringBuilder(cleaned.length());
        for (int i = 0; i < cleaned.length(); i++) {
            char c = cleaned.charAt(i);
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ':' || c == ',') {
                continue;
            }
            if (!isHex(c)) {
                throw new IllegalArgumentException(label + " has a character that is not hex.");
            }
            digits.append(c);
        }
        if (digits.length() == 0) {
            throw new IllegalArgumentException("Enter the " + label + " as hex.");
        }
        if ((digits.length() & 1) != 0) {
            throw new IllegalArgumentException(label + " hex has an odd number of digits.");
        }
        byte[] out = new byte[digits.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(digits.charAt(i * 2), 16);
            int low = Character.digit(digits.charAt(i * 2 + 1), 16);
            out[i] = (byte) ((high << 4) | low);
        }
        return stripLeadingZeros(out);
    }

    static String format(byte[] bytes) {
        if (bytes == null) {
            return "none";
        }
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            text.append(String.format("%02x", value & 0xff));
        }
        return text.toString();
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

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9')
                || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
    }
}
