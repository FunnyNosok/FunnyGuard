package com.protectedclient.loader;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public final class StringVault {

    private static final byte[] VAULT_SALT = {
        (byte) 0xA7, (byte) 0x3E, (byte) 0x11, (byte) 0xC9, (byte) 0x5D, (byte) 0x82, (byte) 0x0F, (byte) 0x64,
        (byte) 0xB1, (byte) 0x2A, (byte) 0xE8, (byte) 0x47, (byte) 0x93, (byte) 0x0C, (byte) 0xD6, (byte) 0x78
    };

    private StringVault() {
    }

    private static byte[] vaultKey() {
        char[] material = KeyManager.buildKeyMaterial(new char[0]);
        byte[][] keys = Crypto.deriveKeys(material, VAULT_SALT);
        Arrays.fill(material, '\0');
        Arrays.fill(keys[1], (byte) 0);
        return keys[0];
    }

    public static String hide(String plaintext) {
        byte[] key = vaultKey();
        byte[] iv = Crypto.randomIv();
        byte[] plain = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] cipher = Crypto.encryptGcm(key, iv, plain);
        Arrays.fill(plain, (byte) 0);
        Arrays.fill(key, (byte) 0);
        byte[] combined = new byte[iv.length + cipher.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipher, 0, combined, iv.length, cipher.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public static String reveal(String token) {
        byte[] key = vaultKey();
        byte[] raw = Base64.getDecoder().decode(token);
        byte[] iv = Arrays.copyOfRange(raw, 0, Crypto.GCM_IV_BYTES);
        byte[] cipher = Arrays.copyOfRange(raw, Crypto.GCM_IV_BYTES, raw.length);
        byte[] plain = Crypto.decryptGcm(key, iv, cipher);
        Arrays.fill(key, (byte) 0);
        String result = new String(plain, StandardCharsets.UTF_8);
        Arrays.fill(plain, (byte) 0);
        return result;
    }
}
