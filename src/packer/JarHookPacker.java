package com.protectedclient.packer;

import com.protectedclient.loader.JarHookFormat;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public final class JarHookPacker {

    private JarHookPacker() {
    }

    public static int rewrite(File inputJar, File outputJar, char[] passphrase) throws IOException {
        byte[] masterKey = JarHookFormat.deriveMasterKey(passphrase);
        int encryptedCount = 0;
        File parent = outputJar.getAbsoluteFile().getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        try (ZipFile zip = new ZipFile(inputJar);
             ZipOutputStream out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(outputJar)))) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                if (isSignatureFile(name)) {
                    continue;
                }

                byte[] original;
                try (InputStream in = zip.getInputStream(entry)) {
                    original = in.readAllBytes();
                }

                byte[] payload;
                if (name.equals("META-INF/MANIFEST.MF")) {
                    payload = stripManifestDigests(original);
                } else if (isEncryptable(entry)) {
                    String className = name.substring(0, name.length() - ".class".length());
                    payload = JarHookFormat.wrap(masterKey, className, original);
                    encryptedCount++;
                } else {
                    payload = original;
                }

                ZipEntry copy = new ZipEntry(name);
                if (entry.getTime() != -1L) {
                    copy.setTime(entry.getTime());
                }
                out.putNextEntry(copy);
                out.write(payload);
                out.closeEntry();
            }
        }
        Arrays.fill(masterKey, (byte) 0);
        return encryptedCount;
    }

    private static byte[] stripManifestDigests(byte[] manifestBytes) throws IOException {
        Manifest manifest = new Manifest(new ByteArrayInputStream(manifestBytes));
        manifest.getEntries().clear();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        manifest.write(out);
        return out.toByteArray();
    }

    private static boolean isSignatureFile(String name) {
        if (!name.startsWith("META-INF/")) {
            return false;
        }
        String upper = name.toUpperCase();
        return upper.endsWith(".SF") || upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC");
    }

    private static boolean isEncryptable(ZipEntry entry) {
        if (entry.isDirectory()) {
            return false;
        }
        String name = entry.getName();
        return name.endsWith(".class") && !name.equals("module-info.class");
    }
}
