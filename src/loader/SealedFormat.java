package com.protectedclient.loader;

import java.nio.ByteBuffer;
import java.util.Arrays;

public final class SealedFormat {

    public static final byte[] MAGIC = { 'P', 'M', 'C', 'H' };
    public static final byte VERSION_SEALED = 3;

    public static final int FILE_KEY_BYTES = 32;
    public static final int SALT_BYTES = 16;
    public static final int SEED_BYTES = 16;
    public static final int IV_BYTES = Crypto.GCM_IV_BYTES;
    public static final int TAG_BYTES = Crypto.GCM_TAG_BITS / 8;

    public static final int HEADER_BYTES = 4 + 1 + SALT_BYTES + SEED_BYTES + IV_BYTES;

    public static final int SEAL_FILE_BYTES = FILE_KEY_BYTES + SALT_BYTES;

    private SealedFormat() {
    }

    public static byte[] randomFileKey() {
        return Crypto.randomBytes(FILE_KEY_BYTES);
    }

    public static byte[] randomSalt() {
        return Crypto.randomBytes(SALT_BYTES);
    }

    public static byte[] randomSeed() {
        return Crypto.randomBytes(SEED_BYTES);
    }

    public static boolean hasSealedMagic(byte[] blob) {
        if (blob == null || blob.length < HEADER_BYTES + TAG_BYTES) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (blob[i] != MAGIC[i]) {
                return false;
            }
        }
        return blob[MAGIC.length] == VERSION_SEALED;
    }

    static byte[] mixKey(byte[] fileKey, byte[] salt16, byte[] seed16) {
        byte[] d = OpaquePredicate.digest(salt16, seed16);
        byte[] kmix = Crypto.hmac(fileKey, d);
        Arrays.fill(d, (byte) 0);
        return kmix;
    }

    public static byte[] wrap(byte[] fileKey, byte[] fileSalt, byte[] classBytes) {
        if (fileKey == null || fileKey.length != FILE_KEY_BYTES) {
            throw new IllegalArgumentException("fileKey must be 32 bytes");
        }
        if (fileSalt == null || fileSalt.length != SALT_BYTES) {
            throw new IllegalArgumentException("fileSalt must be 16 bytes");
        }
        byte[] seed = randomSeed();
        byte[] kmix = mixKey(fileKey, fileSalt, seed);
        byte[] iv = Crypto.randomIv();
        byte[] ct = Crypto.encryptGcm(kmix, iv, classBytes);
        Arrays.fill(kmix, (byte) 0);
        ByteBuffer buf = ByteBuffer.allocate(HEADER_BYTES + ct.length);
        buf.put(MAGIC);
        buf.put(VERSION_SEALED);
        buf.put(fileSalt);
        buf.put(seed);
        buf.put(iv);
        buf.put(ct);
        Arrays.fill(seed, (byte) 0);
        return buf.array();
    }

    public static byte[] unwrap(byte[] fileKey, byte[] blob) {
        if (!hasSealedMagic(blob)) {
            throw new IllegalArgumentException("blob is not a sealed v3 payload");
        }
        if (fileKey == null || fileKey.length != FILE_KEY_BYTES) {
            throw new IllegalArgumentException("fileKey must be 32 bytes");
        }
        byte[] salt = Arrays.copyOfRange(blob, 5, 5 + SALT_BYTES);
        byte[] seed = Arrays.copyOfRange(blob, 5 + SALT_BYTES, 5 + SALT_BYTES + SEED_BYTES);
        byte[] iv = Arrays.copyOfRange(blob, 5 + SALT_BYTES + SEED_BYTES, HEADER_BYTES);
        byte[] ct = Arrays.copyOfRange(blob, HEADER_BYTES, blob.length);
        byte[] kmix = mixKey(fileKey, salt, seed);
        try {
            return Crypto.decryptGcm(kmix, iv, ct);
        } finally {
            Arrays.fill(kmix, (byte) 0);
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(seed, (byte) 0);
        }
    }

    public static byte[] packSealFile(byte[] fileKey, byte[] fileSalt) {
        if (fileKey.length != FILE_KEY_BYTES || fileSalt.length != SALT_BYTES) {
            throw new IllegalArgumentException("bad seal parts");
        }
        byte[] out = new byte[SEAL_FILE_BYTES];
        System.arraycopy(fileKey, 0, out, 0, FILE_KEY_BYTES);
        System.arraycopy(fileSalt, 0, out, FILE_KEY_BYTES, SALT_BYTES);
        return out;
    }

    public static byte[][] unpackSealFile(byte[] raw) {
        if (raw == null || raw.length != SEAL_FILE_BYTES) {
            throw new IllegalArgumentException("seal file must be exactly 48 bytes (key32||salt16)");
        }
        byte[] k = Arrays.copyOfRange(raw, 0, FILE_KEY_BYTES);
        byte[] s = Arrays.copyOfRange(raw, FILE_KEY_BYTES, SEAL_FILE_BYTES);
        return new byte[][] { k, s };
    }

    public static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        if (hex == null || (hex.length() & 1) != 0) {
            throw new IllegalArgumentException("bad hex");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
