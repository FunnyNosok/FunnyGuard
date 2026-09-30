package com.protectedclient.nativecore;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

public final class NativeCore {

    private static volatile boolean loaded = false;

    private NativeCore() {
    }

    public static synchronized void load(String dllPath) {
        if (!loaded) {
            System.load(dllPath);
            loaded = true;
        }
    }

    public static synchronized void loadVerified(String dllPath, String expectHex) {
        String actual = sha256File(dllPath);
        byte[] a = fromHex(actual);
        byte[] b;
        try {
            b = fromHex(expectHex);
        } catch (RuntimeException e) {
            Arrays.fill(a, (byte) 0);
            throw new SecurityException("bad expect hash");
        }
        boolean ok = b.length == 32 && MessageDigest.isEqual(a, b);
        Arrays.fill(a, (byte) 0);
        Arrays.fill(b, (byte) 0);
        if (!ok) {
            throw new SecurityException("dll hash mismatch");
        }
        load(dllPath);
    }

    public static String sha256File(String path) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(Path.of(path))) {
                byte[] buf = new byte[8192];
                int r;
                while ((r = in.read(buf)) > 0) {
                    sha.update(buf, 0, r);
                }
                Arrays.fill(buf, (byte) 0);
            }
            byte[] h = sha.digest();
            String hex = toHex(h);
            Arrays.fill(h, (byte) 0);
            return hex;
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("hash failed", e);
        }
    }

    public static String toHex(byte[] v) {
        StringBuilder sb = new StringBuilder(v.length * 2);
        for (byte x : v) {
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

    public static native boolean antiDebug();

    public static native long secretTransform(long input);

    public static native String issueLicense(String subject);

    public static native String verifyLicense(String token);
}
