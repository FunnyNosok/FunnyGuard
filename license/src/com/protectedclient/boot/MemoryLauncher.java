package com.protectedclient.boot;

import com.protectedclient.loader.ContainerFormat;

import java.lang.reflect.Method;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.security.MessageDigest;

public final class MemoryLauncher {

    private MemoryLauncher() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("usage: MemoryLauncher <serverBase> <token> <secret> <mainClass> [appArgs...]");
            System.exit(2);
        }
        String base = args[0];
        String token = args[1];
        String mainClass = args[3];
        String[] appArgs = Arrays.copyOfRange(args, 4, args.length);

        String hwid = hwid();
        byte[] payload = downloadPayload(base + "/payload", token, hwid);
        System.out.println("[mem-launch] pulled " + payload.length + " bytes (opaque container) into memory (nothing on disk)");

        String pass = System.getenv("PMCH_PASS");
        if (pass == null || pass.isEmpty()) {
            throw new SecurityException("PMCH_PASS not set");
        }
        byte[] containerKey = ContainerFormat.deriveContainerKey(pass.toCharArray());
        Map<String, byte[]> entries = ContainerFormat.unpack(containerKey, payload);
        Arrays.fill(containerKey, (byte) 0);
        Arrays.fill(payload, (byte) 0);
        System.out.println("[mem-launch] container decrypted in memory -> " + entries.size() + " entries");

        MemoryClassLoader loader = MemoryClassLoader.fromEntries(entries, MemoryLauncher.class.getClassLoader());
        System.out.println("[mem-launch] in-memory classes: " + loader.classCount());
        Class<?> c = loader.loadClass(mainClass);
        Method m = c.getMethod("main", String[].class);
        System.out.println("[mem-launch] running " + mainClass + " from memory");
        m.invoke(null, (Object) appArgs);
    }

    private static byte[] downloadPayload(String url, String token, String hwid) throws Exception {
        String body = "token=" + token + "\nhwid=" + hwid + "\ncnonce=0\n";
        HttpClient http = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build();
        HttpResponse<byte[]> res = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (res.statusCode() != 200) {
            throw new SecurityException("payload denied: " + res.statusCode());
        }
        return res.body();
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
