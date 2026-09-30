package com.protectedclient.packer;

import com.protectedclient.loader.CondyStrings;
import com.protectedclient.loader.SealedFormat;
import com.protectedclient.loader.StringVault;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public final class Packer {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            return;
        }
        String command = args[0];
        Map<String, String> options = parseOptions(args);
        switch (command) {
            case "jarhook":
                doJarHook(options);
                break;
            case "container":
                doContainer(options);
                break;
            case "seal":
                doSeal(options);
                break;
            case "vault-seal":
                doVaultSeal(options);
                break;
            case "vault":
                doVault(options);
                break;
            default:
                printUsage();
        }
    }

    private static void doContainer(Map<String, String> options) throws Exception {
        File input = new File(required(options, "--in"));
        File output = new File(required(options, "--out"));
        char[] passphrase = required(options, "--pass").toCharArray();
        if (!input.isFile()) {
            throw new IllegalArgumentException("input jar not found: " + input);
        }
        int encrypted = ContainerPacker.pack(input, output, passphrase);
        Arrays.fill(passphrase, '\0');
        System.out.println("container: packed " + encrypted + " encrypted class(es) into opaque blob " + output.getAbsolutePath());
    }

    private static void doJarHook(Map<String, String> options) throws Exception {
        File input = new File(required(options, "--in"));
        File output = new File(required(options, "--out"));
        char[] passphrase = required(options, "--pass").toCharArray();
        if (!input.isFile()) {
            throw new IllegalArgumentException("input jar not found: " + input);
        }
        int encrypted = JarHookPacker.rewrite(input, output, passphrase);
        Arrays.fill(passphrase, '\0');
        if (encrypted == 0) {
            throw new IllegalStateException("no .class entries found in " + input);
        }
        System.out.println("jarhook: rewrote " + encrypted + " class entr(ies) into " + output.getAbsolutePath());
    }

    private static void doSeal(Map<String, String> options) throws Exception {
        File input = new File(required(options, "--in"));
        File output = new File(required(options, "--out"));
        String keyOut = options.get("--key-out");
        if (keyOut == null) {
            throw new IllegalArgumentException("missing required option --key-out");
        }
        if (!input.isFile()) {
            throw new IllegalArgumentException("input jar not found: " + input);
        }
        SealedPacker.SealResult r = SealedPacker.seal(input, output, new File(keyOut));
        System.out.println("seal: rewrote " + r.encryptedCount + " class entr(ies) into " + output.getAbsolutePath());
        System.out.println("seal: condy strings sealed: " + r.stringsSealed + " in " + r.stringClasses + " class(es)");
        System.out.println("seal: key file (KEEP ON SERVER, never ship to client): " + new File(keyOut).getAbsolutePath());
        System.out.println("seal: fingerprint(key||salt)[sha256:16hex] = " + SealedPacker.fingerprint(r.fileKey, r.fileSalt));
        Arrays.fill(r.fileKey, (byte) 0);
        Arrays.fill(r.fileSalt, (byte) 0);
        if (r.encryptedCount == 0) {
            throw new IllegalStateException("no .class entries found in " + input);
        }
    }

    private static void doVaultSeal(Map<String, String> options) {
        String text = required(options, "--text");
        byte[] key = SealedFormat.fromHex(required(options, "--key-hex"));
        try {
            System.out.println(CondyStrings.seal(text, key));
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static void doVault(Map<String, String> options) {
        String text = required(options, "--text");
        System.out.println(StringVault.hide(text));
    }

    private static Map<String, String> parseOptions(String[] args) {
        Map<String, String> options = new HashMap<>();
        for (int i = 1; i + 1 < args.length; i += 2) {
            options.put(args[i], args[i + 1]);
        }
        return options;
    }

    private static String required(Map<String, String> options, String key) {
        String value = options.get(key);
        if (value == null) {
            throw new IllegalArgumentException("missing required option " + key);
        }
        return value;
    }

    private static void printUsage() {
        System.out.println("Packer commands:");
        System.out.println("  jarhook   --in <jar> --out <jar> --pass <passphrase>");
        System.out.println("  container --in <jar> --out <file.pcc> --pass <passphrase>");
        System.out.println("  seal      --in <jar> --out <sealed.jar> --key-out <seal.key>");
        System.out.println("  vault-seal --text <plaintext> --key-hex <hex(fileKey)>");
        System.out.println("  vault     --text <plaintext>");
    }
}
