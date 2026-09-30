package com.protectedclient.loader;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ContainerFormat {

    public static final byte[] CONTAINER_SALT = {
        (byte) 0xE2, (byte) 0x55, (byte) 0x1A, (byte) 0x8C, (byte) 0x74, (byte) 0xBF, (byte) 0x03, (byte) 0xD9,
        (byte) 0x6E, (byte) 0x21, (byte) 0xCA, (byte) 0x47, (byte) 0x90, (byte) 0x3D, (byte) 0xF6, (byte) 0x18
    };

    private ContainerFormat() {
    }

    public static byte[] deriveContainerKey(char[] passphrase) {
        char[] material = KeyManager.buildKeyMaterial(passphrase);
        byte[][] keys = Crypto.deriveKeys(material, CONTAINER_SALT);
        Arrays.fill(material, '\0');
        Arrays.fill(keys[1], (byte) 0);
        return keys[0];
    }

    public static byte[] pack(byte[] key, Map<String, byte[]> entries) {
        try {
            ByteArrayOutputStream raw = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(raw);
            dos.writeInt(entries.size());
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                dos.writeUTF(e.getKey());
                dos.writeInt(e.getValue().length);
                dos.write(e.getValue());
            }
            dos.flush();
            byte[] plain = raw.toByteArray();
            byte[] iv = Crypto.randomIv();
            byte[] ct = Crypto.encryptGcm(key, iv, plain);
            Arrays.fill(plain, (byte) 0);
            ByteArrayOutputStream out = new ByteArrayOutputStream(iv.length + ct.length);
            out.write(iv);
            out.write(ct);
            return out.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static Map<String, byte[]> unpack(byte[] key, byte[] container) {
        try {
            byte[] iv = Arrays.copyOfRange(container, 0, Crypto.GCM_IV_BYTES);
            byte[] ct = Arrays.copyOfRange(container, Crypto.GCM_IV_BYTES, container.length);
            byte[] plain = Crypto.decryptGcm(key, iv, ct);
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(plain));
            int count = dis.readInt();
            Map<String, byte[]> entries = new LinkedHashMap<>();
            for (int i = 0; i < count; i++) {
                String name = dis.readUTF();
                int len = dis.readInt();
                byte[] payload = new byte[len];
                dis.readFully(payload);
                entries.put(name, payload);
            }
            Arrays.fill(plain, (byte) 0);
            return entries;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
