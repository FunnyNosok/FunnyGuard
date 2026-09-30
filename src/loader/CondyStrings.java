package com.protectedclient.loader;

import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class CondyStrings {

    public static final int SEED_BYTES = 16;

    private static final byte[] DOMAIN = {
        (byte) 0x43, (byte) 0x30, (byte) 0x4E, (byte) 0x44, (byte) 0x59, (byte) 0x2D, (byte) 0x53, (byte) 0x54,
        (byte) 0x52, (byte) 0x2D, (byte) 0x76, (byte) 0x31, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    private static final ThreadLocal<Cipher> DECRYPT_CIPHER = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance("AES/GCM/NoPadding");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    });

    private static final byte[] HOLDER = new byte[SealedFormat.FILE_KEY_BYTES];
    private static volatile boolean installed = false;

    private CondyStrings() {
    }

    public static synchronized void installKey(byte[] fileKey) {
        if (fileKey == null || fileKey.length != SealedFormat.FILE_KEY_BYTES) {
            throw new IllegalArgumentException("fileKey must be 32 bytes");
        }
        System.arraycopy(fileKey, 0, HOLDER, 0, HOLDER.length);
        installed = true;
    }

    public static synchronized void clearKey() {
        Arrays.fill(HOLDER, (byte) 0);
        installed = false;
    }

    public static boolean isInstalled() {
        return installed;
    }

    static byte[] mixKey(byte[] fileKey, byte[] seed16) {
        byte[] d = OpaquePredicate.digest(DOMAIN, seed16);
        byte[] kmix = Crypto.hmac(fileKey, d);
        Arrays.fill(d, (byte) 0);
        return kmix;
    }

    public static String seal(String plaintext, byte[] fileKey) {
        if (plaintext == null || fileKey == null || fileKey.length != SealedFormat.FILE_KEY_BYTES) {
            throw new IllegalArgumentException("bad seal args");
        }
        byte[] seed = Crypto.randomBytes(SEED_BYTES);
        byte[] kmix = mixKey(fileKey, seed);
        byte[] iv = Crypto.randomIv();
        byte[] plain = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] ct = Crypto.encryptGcm(kmix, iv, plain);
        Arrays.fill(kmix, (byte) 0);
        Arrays.fill(plain, (byte) 0);
        byte[] token = new byte[seed.length + iv.length + ct.length];
        System.arraycopy(seed, 0, token, 0, seed.length);
        System.arraycopy(iv, 0, token, seed.length, iv.length);
        System.arraycopy(ct, 0, token, seed.length + iv.length, ct.length);
        Arrays.fill(seed, (byte) 0);
        Arrays.fill(ct, (byte) 0);
        return Base64.getEncoder().encodeToString(token);
    }

    public static String reveal(String token) {
        if (!installed) {
            throw new IllegalStateException("condy key not installed");
        }
        byte[] key;
        synchronized (CondyStrings.class) {
            key = Arrays.copyOf(HOLDER, HOLDER.length);
        }
        try {
            return open(token, key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    public static String bootstrap(MethodHandles.Lookup caller, String name, Class<?> type, String token) {
        if (!installed) {
            autoInstall();
        }
        return reveal(token);
    }

    private static synchronized void autoInstall() {
        if (installed) {
            return;
        }
        String hex = System.getenv("PMCH_SEAL");
        if (hex == null || hex.isEmpty()) {
            throw new IllegalStateException("condy key not installed");
        }
        byte[] key = SealedFormat.fromHex(hex.trim());
        try {
            installKey(key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    static String open(String token, byte[] fileKey) {
        byte[] raw = Base64.getDecoder().decode(token);
        if (raw.length < SEED_BYTES + Crypto.GCM_IV_BYTES + Crypto.GCM_TAG_BITS / 8) {
            throw new IllegalArgumentException("bad condy token");
        }
        byte[] seed = Arrays.copyOfRange(raw, 0, SEED_BYTES);
        byte[] iv = Arrays.copyOfRange(raw, SEED_BYTES, SEED_BYTES + Crypto.GCM_IV_BYTES);
        byte[] ct = Arrays.copyOfRange(raw, SEED_BYTES + Crypto.GCM_IV_BYTES, raw.length);
        Arrays.fill(raw, (byte) 0);
        byte[] kmix = mixKey(fileKey, seed);
        try {
            Cipher c = DECRYPT_CIPHER.get();
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kmix, "AES"), new GCMParameterSpec(Crypto.GCM_TAG_BITS, iv));
            byte[] plain = c.doFinal(ct);
            String out = new String(plain, StandardCharsets.UTF_8);
            Arrays.fill(plain, (byte) 0);
            return out;
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("condy decrypt failed", e);
        } finally {
            Arrays.fill(kmix, (byte) 0);
            Arrays.fill(seed, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(ct, (byte) 0);
        }
    }
}
