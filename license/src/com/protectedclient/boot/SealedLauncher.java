package com.protectedclient.boot;

import com.protectedclient.license.LicenseClient;
import com.protectedclient.loader.SealedFormat;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class SealedLauncher {

    private SealedLauncher() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 5) {
            System.err.println("usage: SealedLauncher <sealUrl> <token> <secret> <sealedJar> <mainClass> [appArgs...]");
            System.exit(2);
        }
        String sealUrl = args[0];
        String token = args[1];
        byte[] secret = args[2].getBytes(StandardCharsets.UTF_8);
        File sealedJar = new File(args[3]);
        String mainClass = args[4];
        String[] appArgs = Arrays.copyOfRange(args, 5, args.length);

        if (!sealedJar.isFile()) {
            throw new IllegalArgumentException("sealed jar not found: " + sealedJar);
        }

        String hwid = hwid();
        byte[] fileKey = LicenseClient.fetchSealedKey(sealUrl, token, secret, hwid);
        Arrays.fill(secret, (byte) 0);
        System.out.println("[sealed-launch] FILE_KEY received (" + fileKey.length + " bytes, hwid-bound, ttl-checked)");

        try {
            verifyFirstClass(sealedJar, fileKey);
            System.out.println("[sealed-launch] fail-fast unwrap ok, spawning protected JDK...");

            String jdkDir = System.getenv("PMCH_JDK");
            String javaExe;
            if (jdkDir != null && !jdkDir.isEmpty()) {
                javaExe = new File(jdkDir, "bin\\java.exe").getAbsolutePath();
                if (!new File(javaExe).isFile()) {
                    javaExe = new File(jdkDir, "bin/java").getAbsolutePath();
                }
            } else {
                javaExe = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
            }

            String wantJvmHash = System.getenv("PMCH_JVM_HASH");
            if (wantJvmHash != null && !wantJvmHash.isEmpty()) {
                verifyJvmHash(jdkDir, wantJvmHash);
                System.out.println("[sealed-launch] jvm hash ok");
            }

            List<String> cmd = new ArrayList<>();
            cmd.add(javaExe);
            cmd.add("-XX:+DisableAttachMechanism");
            cmd.add("-XX:-EnableDynamicAgentLoading");
            cmd.add("--add-exports");
            cmd.add("java.base/jdk.internal.misc=ALL-UNNAMED");
            cmd.add("-cp");
            cmd.add(sealedJar.getAbsolutePath());
            cmd.add(mainClass);
            cmd.addAll(Arrays.asList(appArgs));

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().put("PMCH_SEAL", SealedFormat.toHex(fileKey));
            String guard = System.getenv("PMCH_GUARD");
            pb.environment().put("PMCH_GUARD", guard == null || guard.isEmpty() ? "LOG" : guard);
            pb.inheritIO();
            Process p = pb.start();
            int code = p.waitFor();
            System.out.println("[sealed-launch] exit code: " + code);
            System.exit(code);
        } finally {
            Arrays.fill(fileKey, (byte) 0);
        }
    }

    private static void verifyFirstClass(File jar, byte[] fileKey) throws Exception {
        try (ZipFile zip = new ZipFile(jar)) {
            Enumeration<? extends ZipEntry> e = zip.entries();
            while (e.hasMoreElements()) {
                ZipEntry ze = e.nextElement();
                if (!ze.getName().endsWith(".class")) {
                    continue;
                }
                byte[] blob = zip.getInputStream(ze).readAllBytes();
                if (!SealedFormat.hasSealedMagic(blob)) {
                    continue;
                }
                byte[] plain = SealedFormat.unwrap(fileKey, blob);
                if (plain.length < 8 || (plain[0] & 0xFF) != 0xCA || (plain[1] & 0xFF) != 0xFE) {
                    Arrays.fill(plain, (byte) 0);
                    throw new SecurityException("sealed verify failed: bad class magic in " + ze.getName());
                }
                Arrays.fill(plain, (byte) 0);
                return;
            }
        }
        throw new IllegalStateException("no sealed v3 classes found in " + jar + " (did you run Packer seal?)");
    }

    public static void verifyFileHash(File f, String expectHex) throws Exception {
        if (f == null || !f.isFile()) {
            throw new SecurityException("target not found");
        }
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(f.toPath())) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) > 0) {
                sha.update(buf, 0, r);
            }
            Arrays.fill(buf, (byte) 0);
        }
        byte[] h = sha.digest();
        byte[] want;
        try {
            want = SealedFormat.fromHex(expectHex);
        } catch (RuntimeException e) {
            Arrays.fill(h, (byte) 0);
            throw new SecurityException("bad expect hash");
        }
        boolean ok = want.length == h.length && MessageDigest.isEqual(h, want);
        Arrays.fill(h, (byte) 0);
        Arrays.fill(want, (byte) 0);
        if (!ok) {
            throw new SecurityException("hash mismatch: " + f.getAbsolutePath());
        }
    }

    private static void verifyJvmHash(String jdkDir, String expectHex) throws Exception {
        String base = (jdkDir != null && !jdkDir.isEmpty()) ? jdkDir : System.getProperty("java.home");
        String[] cands = {
            "bin\\server\\jvm.dll",
            "bin/server/jvm.dll",
            "lib\\server\\jvm.dll",
            "lib/server/libjvm.so"
        };
        for (String c : cands) {
            File f = new File(base, c);
            if (f.isFile()) {
                verifyFileHash(f, expectHex);
                return;
            }
        }
        throw new SecurityException("jvm binary not found under " + base);
    }

    private static String hwid() throws Exception {
        String raw = System.getenv("COMPUTERNAME") + "|"
            + System.getProperty("user.name") + "|"
            + System.getProperty("os.arch") + "|"
            + Runtime.getRuntime().availableProcessors();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(raw.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte x : h) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.substring(0, 32);
    }
}
