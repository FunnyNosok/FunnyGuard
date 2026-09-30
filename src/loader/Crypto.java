package com.protectedclient.loader;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public final class Crypto {

    public static final int GCM_TAG_BITS = 128;
    public static final int GCM_IV_BYTES = 12;
    public static final int PBKDF2_ITERATIONS = 210_000;
    public static final int DERIVED_BITS = 512;
    public static final int AES_KEY_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Crypto() {
    }

    public static byte[] randomIv() {
        byte[] iv = new byte[GCM_IV_BYTES];
        RANDOM.nextBytes(iv);
        return iv;
    }

    public static byte[] randomBytes(int count) {
        byte[] out = new byte[count];
        RANDOM.nextBytes(out);
        return out;
    }

    public static byte[][] deriveKeys(char[] material, byte[] salt) {
        PBEKeySpec spec = null;
        try {
            spec = new PBEKeySpec(material, salt, PBKDF2_ITERATIONS, DERIVED_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] block = factory.generateSecret(spec).getEncoded();
            byte[] encKey = Arrays.copyOfRange(block, 0, AES_KEY_BYTES);
            byte[] macKey = Arrays.copyOfRange(block, AES_KEY_BYTES, AES_KEY_BYTES * 2);
            Arrays.fill(block, (byte) 0);
            return new byte[][] { encKey, macKey };
        } catch (Exception e) {
            throw new IllegalStateException("key derivation failed", e);
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
        }
    }

    public static byte[] encryptGcm(byte[] key, byte[] iv, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new IllegalStateException("gcm encrypt failed", e);
        }
    }

    public static byte[] decryptGcm(byte[] key, byte[] iv, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new SecurityException("gcm decrypt failed", e);
        }
    }

    public static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("hmac failed", e);
        }
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
}
