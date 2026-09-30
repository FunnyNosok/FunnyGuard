package com.protectedclient.loader;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public final class EphemeralSession implements AutoCloseable {

    private static final class Child extends ClassLoader {
        private final Map<String, byte[]> defs = new HashMap<>();
        private final byte[] fileKey;
        private boolean closed;

        Child(ClassLoader parent, byte[] fileKey) {
            super(parent);
            this.fileKey = fileKey;
        }

        void add(String name, byte[] sealedBlob) {
            if (closed) {
                throw new IllegalStateException("closed");
            }
            defs.put(name, sealedBlob);
        }

        void wipe() {
            for (byte[] b : defs.values()) {
                Arrays.fill(b, (byte) 0);
            }
            defs.clear();
            Arrays.fill(fileKey, (byte) 0);
            closed = true;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] blob = defs.remove(name);
            if (blob == null || closed) {
                if (blob != null) {
                    Arrays.fill(blob, (byte) 0);
                }
                throw new ClassNotFoundException(name);
            }
            byte[] plain;
            try {
                plain = SealedFormat.unwrap(fileKey, blob);
            } catch (IllegalArgumentException | SecurityException e) {
                throw new ClassNotFoundException(name, e);
            } finally {
                Arrays.fill(blob, (byte) 0);
            }
            try {
                return defineClass(name, plain, 0, plain.length);
            } finally {
                Arrays.fill(plain, (byte) 0);
            }
        }
    }

    private final Child child;
    private boolean closed;

    private EphemeralSession(Child child) {
        this.child = child;
    }

    public static EphemeralSession open(ClassLoader parent, byte[] fileKey) {
        if (fileKey == null || fileKey.length != SealedFormat.FILE_KEY_BYTES) {
            throw new IllegalArgumentException("fileKey must be 32 bytes");
        }
        return new EphemeralSession(new Child(parent, Arrays.copyOf(fileKey, fileKey.length)));
    }

    public Class<?> load(String name, byte[] sealedBlob) throws ClassNotFoundException {
        if (closed) {
            throw new IllegalStateException("closed");
        }
        child.add(name, Arrays.copyOf(sealedBlob, sealedBlob.length));
        return Class.forName(name, true, child);
    }

    public Object invokeMain(String name, byte[] sealedBlob, String[] args) throws Throwable {
        return HiddenLoader.invokeMain(load(name, sealedBlob), args);
    }

    public ClassLoader loader() {
        return child;
    }

    public boolean isClosed() {
        return closed;
    }

    @Override
    public void close() {
        closed = true;
        child.wipe();
    }
}
