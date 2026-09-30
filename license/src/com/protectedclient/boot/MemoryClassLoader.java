package com.protectedclient.boot;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class MemoryClassLoader extends ClassLoader {

    private final Map<String, byte[]> classBytes = new HashMap<>();
    private final Map<String, byte[]> resources = new HashMap<>();

    private MemoryClassLoader(ClassLoader parent) {
        super(parent);
    }

    public static MemoryClassLoader fromJar(byte[] jarBytes, ClassLoader parent) throws IOException {
        MemoryClassLoader loader = new MemoryClassLoader(parent);
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(jarBytes))) {
            ZipEntry entry;
            while ((entry = zin.getNextEntry()) != null) {
                if (!entry.isDirectory()) {
                    loader.put(entry.getName(), zin.readAllBytes());
                }
            }
        }
        return loader;
    }

    public static MemoryClassLoader fromEntries(Map<String, byte[]> entries, ClassLoader parent) {
        MemoryClassLoader loader = new MemoryClassLoader(parent);
        for (Map.Entry<String, byte[]> e : entries.entrySet()) {
            loader.put(e.getKey(), e.getValue());
        }
        return loader;
    }

    private void put(String name, byte[] data) {
        if (name.endsWith(".class")) {
            classBytes.put(name.substring(0, name.length() - 6).replace('/', '.'), data);
        } else {
            resources.put(name, data);
        }
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] b = classBytes.get(name);
        if (b == null) {
            throw new ClassNotFoundException(name);
        }
        return defineClass(name, b, 0, b.length);
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        byte[] b = resources.get(name);
        if (b != null) {
            return new ByteArrayInputStream(b);
        }
        return super.getResourceAsStream(name);
    }

    public int classCount() {
        return classBytes.size();
    }
}
