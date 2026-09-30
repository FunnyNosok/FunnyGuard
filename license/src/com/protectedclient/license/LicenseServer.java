package com.protectedclient.license;

import com.protectedclient.loader.Crypto;
import com.protectedclient.loader.SealedFormat;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class LicenseServer {

    private static final class User {
        final byte[] secret;
        volatile String boundHwid;
        volatile boolean active;
        User(byte[] secret) { this.secret = secret; this.active = true; }
    }

    private static final Map<String, User> USERS = new ConcurrentHashMap<>();
    private static final String RELEASE_PASSPHRASE = "mc-pass-2024";
    private static byte[] payload = new byte[0];
    private static volatile byte[] sealedFileKey = null;
    private static final long SEAL_TTL_SEC = 120L;

    private LicenseServer() {
    }

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8077;
        if (args.length > 1 && !args[1].isEmpty()) {
            payload = Files.readAllBytes(Path.of(args[1]));
        }
        if (args.length > 2 && !args[2].isEmpty()) {
            byte[] raw = Files.readAllBytes(Path.of(args[2]));
            byte[][] parts = SealedFormat.unpackSealFile(raw);
            sealedFileKey = parts[0];
            java.util.Arrays.fill(raw, (byte) 0);
            java.util.Arrays.fill(parts[1], (byte) 0);
        }

        byte[] demoSecret = "FUNNYGUARD-DEMO-SECRET-32bytes!!".getBytes(StandardCharsets.UTF_8);
        USERS.put("USER-001", new User(demoSecret));

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/license", LicenseServer::handleLicense);
        server.createContext("/payload", LicenseServer::handlePayload);
        server.createContext("/seal", LicenseServer::handleSeal);
        server.setExecutor(null);
        server.start();
        System.out.println("[license-server] listening on http://127.0.0.1:" + port);
        System.out.println("[license-server] payload bytes available: " + payload.length);
        System.out.println("[license-server] sealed mode: " + (sealedFileKey != null ? "ON (per-launch FILE_KEY, ttl=" + SEAL_TTL_SEC + "s)" : "OFF (pass seal.key as 3rd arg to enable)"));
    }

    private static User authorize(Map<String, String> req) {
        String token = req.get("token");
        String hwid = req.get("hwid");
        if (token == null || hwid == null) {
            return null;
        }
        User user = USERS.get(token);
        if (user == null || !user.active) {
            System.out.println("[license-server] DENY token=" + token + " (unknown/inactive)");
            return null;
        }
        if (user.boundHwid == null) {
            user.boundHwid = hwid;
            System.out.println("[license-server] bound token=" + token + " to hwid=" + hwid);
        } else if (!user.boundHwid.equals(hwid)) {
            System.out.println("[license-server] DENY token=" + token + " (hwid mismatch)");
            return null;
        }
        return user;
    }

    private static void handleLicense(HttpExchange ex) throws IOException {
        try {
            if (!"POST".equals(ex.getRequestMethod())) { respond(ex, 405, "method not allowed".getBytes()); return; }
            Map<String, String> req = parse(readBody(ex.getRequestBody()));
            User user = authorize(req);
            if (user == null) { respond(ex, 403, "denied".getBytes(StandardCharsets.UTF_8)); return; }

            String cnonce = req.get("cnonce");
            String snonce = toHex(Crypto.randomBytes(16));
            byte[] ks = Crypto.hmac(user.secret, (cnonce + snonce).getBytes(StandardCharsets.UTF_8));
            byte[] iv = Crypto.randomIv();
            byte[] ct = Crypto.encryptGcm(ks, iv, RELEASE_PASSPHRASE.getBytes(StandardCharsets.UTF_8));

            String sb = "snonce=" + snonce + "\n"
                + "iv=" + Base64.getEncoder().encodeToString(iv) + "\n"
                + "data=" + Base64.getEncoder().encodeToString(ct) + "\n";
            System.out.println("[license-server] GRANT key token=" + req.get("token"));
            respond(ex, 200, sb.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            respond(ex, 500, "error".getBytes());
        }
    }

    private static void handlePayload(HttpExchange ex) throws IOException {
        try {
            if (!"POST".equals(ex.getRequestMethod())) { respond(ex, 405, "method not allowed".getBytes()); return; }
            Map<String, String> req = parse(readBody(ex.getRequestBody()));
            User user = authorize(req);
            if (user == null) { respond(ex, 403, "denied".getBytes(StandardCharsets.UTF_8)); return; }
            System.out.println("[license-server] GRANT payload token=" + req.get("token") + " (" + payload.length + " bytes)");
            ex.getResponseHeaders().set("Content-Type", "application/octet-stream");
            respond(ex, 200, payload);
        } catch (Exception e) {
            respond(ex, 500, "error".getBytes());
        }
    }

    private static void handleSeal(HttpExchange ex) throws IOException {
        try {
            if (!"POST".equals(ex.getRequestMethod())) { respond(ex, 405, "method not allowed".getBytes()); return; }
            if (sealedFileKey == null) { respond(ex, 404, "sealed mode off".getBytes(StandardCharsets.UTF_8)); return; }
            Map<String, String> req = parse(readBody(ex.getRequestBody()));
            User user = authorize(req);
            if (user == null) { respond(ex, 403, "denied".getBytes(StandardCharsets.UTF_8)); return; }

            String cnonce = req.get("cnonce");
            String hwid = req.get("hwid");
            if (cnonce == null || hwid == null) { respond(ex, 400, "bad request".getBytes()); return; }
            String snonce = toHex(Crypto.randomBytes(16));
            byte[] ks = Crypto.hmac(user.secret, (cnonce + snonce).getBytes(StandardCharsets.UTF_8));
            long expiry = System.currentTimeMillis() / 1000L + SEAL_TTL_SEC;
            String plain = "key=" + Base64.getEncoder().encodeToString(sealedFileKey) + "\n"
                + "expiry=" + expiry + "\n"
                + "hwid=" + hwid + "\n";
            byte[] iv = Crypto.randomIv();
            byte[] ct = Crypto.encryptGcm(ks, iv, plain.getBytes(StandardCharsets.UTF_8));
            java.util.Arrays.fill(ks, (byte) 0);

            String sb = "snonce=" + snonce + "\n"
                + "iv=" + Base64.getEncoder().encodeToString(iv) + "\n"
                + "data=" + Base64.getEncoder().encodeToString(ct) + "\n";
            System.out.println("[license-server] GRANT seal token=" + req.get("token") + " expiry=" + expiry);
            respond(ex, 200, sb.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            respond(ex, 500, "error".getBytes());
        }
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

    private static String readBody(InputStream in) throws IOException {
        return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }

    private static void respond(HttpExchange ex, int code, byte[] body) throws IOException {
        ex.sendResponseHeaders(code, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
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
