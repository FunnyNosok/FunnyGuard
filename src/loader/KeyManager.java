package com.protectedclient.loader;

import java.util.Arrays;
import java.util.Base64;

public final class KeyManager {

    private static final byte[] PART_A = {
        (byte) 0x9F, (byte) 0x11, (byte) 0x4C, (byte) 0xA2, (byte) 0x03, (byte) 0xE8, (byte) 0x77, (byte) 0x5B,
        (byte) 0x2D, (byte) 0xC0, (byte) 0x64, (byte) 0x91, (byte) 0xBA, (byte) 0x38, (byte) 0x0F, (byte) 0xD7,
        (byte) 0x46, (byte) 0xE1, (byte) 0x82, (byte) 0x59, (byte) 0x1C, (byte) 0xAF, (byte) 0x73, (byte) 0x6A,
        (byte) 0xD4, (byte) 0x08, (byte) 0x95, (byte) 0x3B, (byte) 0xCE, (byte) 0x27, (byte) 0x50, (byte) 0xB9
    };

    private static final byte[] PART_B = {
        (byte) 0x31, (byte) 0x7A, (byte) 0xE5, (byte) 0x0C, (byte) 0x88, (byte) 0x4F, (byte) 0x1D, (byte) 0xC6,
        (byte) 0x93, (byte) 0x2A, (byte) 0xB7, (byte) 0x60, (byte) 0x05, (byte) 0xD9, (byte) 0x4E, (byte) 0x8B,
        (byte) 0x12, (byte) 0xF3, (byte) 0x6C, (byte) 0xA5, (byte) 0x39, (byte) 0x80, (byte) 0xE7, (byte) 0x1E,
        (byte) 0x57, (byte) 0xCB, (byte) 0x24, (byte) 0x9D, (byte) 0x70, (byte) 0xB2, (byte) 0x4A, (byte) 0x03
    };

    private static final byte[] PART_C = {
        (byte) 0x6D, (byte) 0x2C, (byte) 0xF1, (byte) 0x58, (byte) 0x94, (byte) 0x0B, (byte) 0xA6, (byte) 0x3F,
        (byte) 0xE2, (byte) 0x79, (byte) 0x10, (byte) 0xCD, (byte) 0x66, (byte) 0x87, (byte) 0x3A, (byte) 0xF4,
        (byte) 0x5B, (byte) 0x0E, (byte) 0xD1, (byte) 0x28, (byte) 0xB5, (byte) 0x4C, (byte) 0x99, (byte) 0x62,
        (byte) 0x07, (byte) 0xEA, (byte) 0x83, (byte) 0x3E, (byte) 0xC1, (byte) 0x74, (byte) 0x1F, (byte) 0xA8
    };

    private KeyManager() {
    }

    public static byte[] embeddedSecret() {
        int length = PART_A.length;
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (PART_A[i] ^ PART_B[i] ^ PART_C[i]);
        }
        return out;
    }

    public static char[] buildKeyMaterial(char[] passphrase) {
        byte[] secret = embeddedSecret();
        String encoded = Base64.getEncoder().encodeToString(secret);
        Arrays.fill(secret, (byte) 0);
        char[] encodedChars = encoded.toCharArray();
        char[] safePass = passphrase == null ? new char[0] : passphrase;
        char[] combined = new char[safePass.length + encodedChars.length];
        System.arraycopy(safePass, 0, combined, 0, safePass.length);
        System.arraycopy(encodedChars, 0, combined, safePass.length, encodedChars.length);
        Arrays.fill(encodedChars, '\0');
        return combined;
    }
}
