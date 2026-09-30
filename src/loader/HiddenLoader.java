package com.protectedclient.loader;

import java.lang.invoke.MethodHandles;
import java.util.Arrays;

public final class HiddenLoader {

    private HiddenLoader() {
    }

    public static Class<?> defineSealed(MethodHandles.Lookup caller, byte[] sealedBlob, byte[] fileKey) throws Throwable {
        byte[] plain = SealedFormat.unwrap(fileKey, sealedBlob);
        try {
            return caller.defineHiddenClass(plain, true, MethodHandles.Lookup.ClassOption.NESTMATE).lookupClass();
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    public static Class<?> definePlain(MethodHandles.Lookup caller, byte[] classBytes) throws IllegalAccessException {
        try {
            return caller.defineHiddenClass(classBytes, true, MethodHandles.Lookup.ClassOption.NESTMATE).lookupClass();
        } finally {
            Arrays.fill(classBytes, (byte) 0);
        }
    }

    public static Object invokeMain(Class<?> hidden, String[] args) throws Throwable {
        return hidden.getMethod("main", String[].class).invoke(null, (Object) args);
    }

    public static boolean isHidden(Class<?> c) {
        return c.isHidden();
    }
}
