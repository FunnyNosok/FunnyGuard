package com.protectedclient.packer;

import com.protectedclient.loader.SealedFormat;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public final class SealedPacker {

    private SealedPacker() {
    }

    public static final class SealResult {
        public final int encryptedCount;
        public final int stringClasses;
        public final int stringsSealed;
        public final byte[] fileKey;
        public final byte[] fileSalt;

        SealResult(int n, int sc, int ss, byte[] k, byte[] s) {
            this.encryptedCount = n;
            this.stringClasses = sc;
            this.stringsSealed = ss;
            this.fileKey = k;
            this.fileSalt = s;
        }
    }

    public static SealResult seal(File inputJar, File outputJar, File keyFile) throws IOException {
        byte[] fileKey = SealedFormat.randomFileKey();
        byte[] fileSalt = SealedFormat.randomSalt();
        int n = 0;
        int stringClasses = 0;
        int stringsSealed = 0;

        File parent = outputJar.getAbsoluteFile().getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        File kp = keyFile.getAbsoluteFile().getParentFile();
        if (kp != null) {
            kp.mkdirs();
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
                    CondySeal.Result cr = CondySeal.sealStrings(original, fileKey);
                    payload = SealedFormat.wrap(fileKey, fileSalt, cr.bytes);
                    if (cr.bytes != original) {
                        Arrays.fill(cr.bytes, (byte) 0);
                    }
                    Arrays.fill(original, (byte) 0);
                    n++;
                    stringsSealed += cr.sealed;
                    if (cr.sealed > 0) {
                        stringClasses++;
                    }
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

        byte[] sealFile = SealedFormat.packSealFile(fileKey, fileSalt);
        Files.write(keyFile.toPath(), sealFile);
        Arrays.fill(sealFile, (byte) 0);
        return new SealResult(n, stringClasses, stringsSealed, fileKey, fileSalt);
    }

    public static String fingerprint(byte[] fileKey, byte[] fileSalt) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(fileKey);
            sha.update(fileSalt);
            byte[] h = sha.digest();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                sb.append(Character.forDigit((h[i] >> 4) & 0xF, 16));
                sb.append(Character.forDigit(h[i] & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
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
