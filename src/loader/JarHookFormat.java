package com.protectedclient.loader;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class JarHookFormat {

    public static final byte[] MAGIC = { 'P', 'M', 'C', 'H' };
    public static final byte VERSION = 2;
    public static final int IV_BYTES = Crypto.GCM_IV_BYTES;
    public static final int TAG_BYTES = Crypto.GCM_TAG_BITS / 8;
    public static final int HEADER_BYTES = MAGIC.length + 1 + IV_BYTES;

    public static final byte[] SALT = {
        (byte) 0x4A, (byte) 0x1C, (byte) 0xF7, (byte) 0x82, (byte) 0x30, (byte) 0x6B, (byte) 0xD5, (byte) 0x9E,
        (byte) 0x07, (byte) 0xC4, (byte) 0x51, (byte) 0xA8, (byte) 0x2F, (byte) 0xE3, (byte) 0x18, (byte) 0x7D
    };

    private JarHookFormat() {
    }

    public static byte[] deriveMasterKey(char[] passphrase) {
        char[] material = KeyManager.buildKeyMaterial(passphrase);
        byte[][] keys = Crypto.deriveKeys(material, SALT);
        Arrays.fill(material, '\0');
        Arrays.fill(keys[1], (byte) 0);
        return keys[0];
    }

    public static byte[] classKey(byte[] masterKey, String className) {
        return Crypto.hmac(masterKey, className.getBytes(StandardCharsets.UTF_8));
    }

    public static boolean hasMagic(byte[] blob) {
        if (blob == null || blob.length < HEADER_BYTES + TAG_BYTES) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (blob[i] != MAGIC[i]) {
                return false;
            }
        }
        return blob[MAGIC.length] == VERSION;
    }

    public static byte[] wrap(byte[] masterKey, String className, byte[] classBytes) {
        byte[] key = classKey(masterKey, className);
        byte[] iv = Crypto.randomIv();
        byte[] ciphertextWithTag = Crypto.encryptGcm(key, iv, classBytes);
        Arrays.fill(key, (byte) 0);
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_BYTES + ciphertextWithTag.length);
        buffer.put(MAGIC);
        buffer.put(VERSION);
        buffer.put(iv);
        buffer.put(ciphertextWithTag);
        return buffer.array();
    }

    public static byte[] unwrap(byte[] masterKey, String className, byte[] blob) {
        if (!hasMagic(blob)) {
            throw new IllegalArgumentException("blob is not a jarhook payload");
        }
        byte[] key = classKey(masterKey, className);
        byte[] iv = Arrays.copyOfRange(blob, MAGIC.length + 1, HEADER_BYTES);
        byte[] ciphertextWithTag = Arrays.copyOfRange(blob, HEADER_BYTES, blob.length);
        byte[] out = Crypto.decryptGcm(key, iv, ciphertextWithTag);
        Arrays.fill(key, (byte) 0);
        return out;
    }
}
