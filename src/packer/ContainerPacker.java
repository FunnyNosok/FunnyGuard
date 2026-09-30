package com.protectedclient.packer;

import com.protectedclient.loader.ContainerFormat;
import com.protectedclient.loader.JarHookFormat;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class ContainerPacker {

    private ContainerPacker() {
    }

    public static int pack(File inputJar, File outputContainer, char[] passphrase) throws IOException {
        byte[] masterKey = JarHookFormat.deriveMasterKey(passphrase);
        byte[] containerKey = ContainerFormat.deriveContainerKey(passphrase);
        Map<String, byte[]> entries = new LinkedHashMap<>();
        int encrypted = 0;

        try (ZipFile zip = new ZipFile(inputJar)) {
            Enumeration<? extends ZipEntry> e = zip.entries();
            while (e.hasMoreElements()) {
                ZipEntry entry = e.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                byte[] data;
                try (InputStream in = zip.getInputStream(entry)) {
                    data = in.readAllBytes();
                }
                if (name.endsWith(".class") && !name.equals("module-info.class")) {
                    String className = name.substring(0, name.length() - ".class".length());
                    entries.put(name, JarHookFormat.wrap(masterKey, className, data));
                    encrypted++;
                } else if (name.startsWith("META-INF/") && isSignature(name)) {
                    continue;
                } else {
                    entries.put(name, data);
                }
            }
        }

        byte[] container = ContainerFormat.pack(containerKey, entries);
        File parent = outputContainer.getAbsoluteFile().getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        Files.write(outputContainer.toPath(), container);
        Arrays.fill(masterKey, (byte) 0);
        Arrays.fill(containerKey, (byte) 0);
        return encrypted;
    }

    private static boolean isSignature(String name) {
        String u = name.toUpperCase();
        return u.endsWith(".SF") || u.endsWith(".RSA") || u.endsWith(".DSA") || u.endsWith(".EC");
    }
}
