package com.protectedclient.loader;

import java.security.MessageDigest;
import java.util.Arrays;

public final class OpaquePredicate {

    public static final long FERMAT_P = 2147483647L;

    private static final long FNV_OFFSET = 0xCBF29CE484222325L;
    private static final long FNV_PRIME = 0x100000001B3L;
    private static final long GOLDEN = 0x9E3779B97F4A7C15L;

    public static final long COLLATZ_STEP_CAP = 5000L;

    private OpaquePredicate() {
    }

    public static long fnv1a64(byte[]... parts) {
        long h = FNV_OFFSET;
        for (byte[] p : parts) {
            for (byte b : p) {
                h ^= (b & 0xFFL);
                h *= FNV_PRIME;
            }
        }
        return h;
    }

    public static long modPow(long base, long exp, long mod) {
        long res = 1 % mod;
        long b = Long.remainderUnsigned(base, mod);
        long e = exp;
        while (e > 0) {
            if ((e & 1L) != 0) {
                res = Long.remainderUnsigned(res * b, mod);
            }
            b = Long.remainderUnsigned(b * b, mod);
            e >>>= 1;
        }
        return res;
    }

    public static final class Trace {
        public final long modexp;
        public final long steps;
        public final long accum;

        Trace(long modexp, long steps, long accum) {
            this.modexp = modexp;
            this.steps = steps;
            this.accum = accum;
        }
    }

    public static Trace trace(byte[] salt16, byte[] seed16) {
        if (salt16 == null || salt16.length != 16 || seed16 == null || seed16.length != 16) {
            throw new IllegalArgumentException("salt and seed must be 16 bytes each");
        }
        long h = fnv1a64(salt16, seed16);

        long base = Long.remainderUnsigned(h, FERMAT_P - 2) + 2;
        long modexp = modPow(base, FERMAT_P - 1, FERMAT_P);

        long seedMix = fnv1a64(seed16) & 0xFFFFL;
        long n = ((h & 0xFFFFFFL) | 1L) + seedMix + 1L;
        long steps = 0;
        long accum = GOLDEN;
        while (n != 1L && steps < COLLATZ_STEP_CAP) {
            accum ^= n + GOLDEN + (accum << 6) + (accum >>> 2);
            if ((n & 1L) == 0L) {
                n = n >>> 1;
            } else {
                n = 3L * n + 1L;
            }
            steps++;
        }
        return new Trace(modexp, steps, accum);
    }

    public static byte[] digest(byte[] salt16, byte[] seed16) {
        Trace t = trace(salt16, seed16);
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(salt16);
            sha.update(seed16);
            sha.update(le64(t.modexp));
            sha.update(le64(t.steps));
            sha.update(le64(t.accum));
            return sha.digest();
        } catch (Exception e) {
            throw new IllegalStateException("sha-256 unavailable", e);
        }
    }

    static byte[] le64(long v) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (v & 0xFFL);
            v >>>= 8;
        }
        return out;
    }

    public static boolean selfTest() {
        byte[] s = new byte[16];
        byte[] d = new byte[16];
        for (int i = 0; i < 16; i++) {
            s[i] = (byte) i;
            d[i] = (byte) (0xA0 + i);
        }
        Trace t = trace(s, d);
        byte[] dg = digest(s, d);
        Arrays.fill(dg, (byte) 0);
        return t.modexp == 1L && t.steps > 0 && t.steps < COLLATZ_STEP_CAP;
    }
}
