package com.protectedclient.license;

import com.protectedclient.loader.Crypto;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public final class LicenseClient {

    private LicenseClient() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("usage: LicenseClient <serverUrl> <token> <secret> [hwidOverride]");
            System.exit(2);
        }
        String serverUrl = args[0];
        String token = args[1];
        byte[] secret = args[2].getBytes(StandardCharsets.UTF_8);
        String hwid = args.length > 3 ? args[3] : computeHwid();

        String passphrase = fetchKey(serverUrl, token, secret, hwid);
        System.out.println(passphrase);
    }

    public static String fetchKey(String serverUrl, String token, byte[] secret, String hwid) throws Exception {
        String cnonce = toHex(Crypto.randomBytes(16));
        String body = "token=" + token + "\nhwid=" + hwid + "\ncnonce=" + cnonce + "\n";

        HttpClient http = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(serverUrl))
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new SecurityException("license denied: " + response.statusCode() + " " + response.body().trim());
        }

        Map<String, String> res = parse(response.body());
        String snonce = res.get("snonce");
        byte[] iv = Base64.getDecoder().decode(res.get("iv"));
        byte[] data = Base64.getDecoder().decode(res.get("data"));

        byte[] ks = Crypto.hmac(secret, (cnonce + snonce).getBytes(StandardCharsets.UTF_8));
        byte[] plain = Crypto.decryptGcm(ks, iv, data);
        java.util.Arrays.fill(ks, (byte) 0);
        String out = new String(plain, StandardCharsets.UTF_8);
        java.util.Arrays.fill(plain, (byte) 0);
        return out;
    }

    public static byte[] fetchSealedKey(String sealUrl, String token, byte[] secret, String hwid) throws Exception {
        String cnonce = toHex(Crypto.randomBytes(16));
        String body = "token=" + token + "\nhwid=" + hwid + "\ncnonce=" + cnonce + "\n";

        HttpClient http = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(sealUrl))
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new SecurityException("seal denied: " + response.statusCode() + " " + response.body().trim());
        }

        Map<String, String> res = parse(response.body());
        String snonce = res.get("snonce");
        byte[] iv = Base64.getDecoder().decode(res.get("iv"));
        byte[] data = Base64.getDecoder().decode(res.get("data"));

        byte[] ks = Crypto.hmac(secret, (cnonce + snonce).getBytes(StandardCharsets.UTF_8));
        byte[] plain = Crypto.decryptGcm(ks, iv, data);
        java.util.Arrays.fill(ks, (byte) 0);
        Map<String, String> inner = parse(new String(plain, StandardCharsets.UTF_8));
        java.util.Arrays.fill(plain, (byte) 0);

        String gotHwid = inner.get("hwid");
        String expiryS = inner.get("expiry");
        String keyB64 = inner.get("key");
        if (gotHwid == null || expiryS == null || keyB64 == null) {
            throw new SecurityException("seal response malformed");
        }
        if (!gotHwid.equals(hwid)) {
            throw new SecurityException("seal hwid mismatch");
        }
        long expiry = Long.parseLong(expiryS.trim());
        long now = System.currentTimeMillis() / 1000L;
        if (now > expiry) {
            throw new SecurityException("seal key expired");
        }
        byte[] key = Base64.getDecoder().decode(keyB64);
        if (key.length != 32) {
            java.util.Arrays.fill(key, (byte) 0);
            throw new SecurityException("seal key bad length");
        }
        return key;
    }

    private static String computeHwid() throws Exception {
        String raw = System.getenv("COMPUTERNAME") + "|"
            + System.getProperty("user.name") + "|"
            + System.getProperty("os.arch") + "|"
            + Runtime.getRuntime().availableProcessors();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(raw.getBytes(StandardCharsets.UTF_8));
        return toHex(h).substring(0, 32);
    }

    private static Map<String, String> parse(String body) {
        Map<String, String> map = new HashMap<>();
        for (String line : body.split("\n")) {
            int eq = line.indexOf('=');
            if (eq > 0) {
                map.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
        }
        return map;
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}
