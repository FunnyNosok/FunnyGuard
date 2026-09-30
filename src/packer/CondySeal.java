package com.protectedclient.packer;

import com.protectedclient.loader.CondyStrings;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class CondySeal {

    public static final int MIN_MAJOR = 55;

    private static final int TAG_UTF8 = 1;
    private static final int TAG_LONG = 5;
    private static final int TAG_DOUBLE = 6;
    private static final int TAG_CLASS = 7;
    private static final int TAG_STRING = 8;
    private static final int TAG_METHODREF = 10;
    private static final int TAG_NAMEANDTYPE = 12;
    private static final int TAG_METHODHANDLE = 15;
    private static final int TAG_DYNAMIC = 17;

    private static final int REF_INVOKE_STATIC = 6;
    private static final int SHARED_COUNT = 10;

    private static final String BSM_CLASS = "com/protectedclient/loader/CondyStrings";
    private static final String BSM_METHOD = "bootstrap";
    private static final String BSM_DESC = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;";
    private static final String BSM_ATTR = "BootstrapMethods";
    private static final String HIDDEN_NAME = "_";
    private static final String STRING_DESC = "Ljava/lang/String;";

    public static final class Result {
        public final byte[] bytes;
        public final int sealed;

        Result(byte[] bytes, int sealed) {
            this.bytes = bytes;
            this.sealed = sealed;
        }
    }

    private CondySeal() {
    }

    public static Result sealStrings(byte[] classBytes, byte[] fileKey) {
        if (classBytes == null || classBytes.length < 10 || u4(classBytes, 0) != 0xCAFEBABE) {
            throw new IllegalArgumentException("bad class");
        }
        if (u2(classBytes, 6) < MIN_MAJOR) {
            return new Result(classBytes, 0);
        }
        if (fileKey == null || fileKey.length != 32) {
            throw new IllegalArgumentException("fileKey must be 32 bytes");
        }
        Pool pool = Pool.parse(classBytes);
        List<Integer> targets = new ArrayList<>();
        for (int i = 1; i < pool.count; i++) {
            if (pool.tag[i] != TAG_STRING || pool.excluded.contains(i)) {
                continue;
            }
            if (pool.utf8Len(pool.stringIndex(i)) == 0) {
                continue;
            }
            targets.add(i);
        }
        if (targets.isEmpty()) {
            return new Result(classBytes, 0);
        }
        Map<Integer, List<Integer>> backrefs = new HashMap<>();
        for (int i = 1; i < pool.count; i++) {
            for (int r : cpRefs(pool, i)) {
                backrefs.computeIfAbsent(r, k -> new ArrayList<>()).add(i);
            }
        }
        Set<Integer> targetSet = new HashSet<>(targets);
        Set<Integer> blank = new HashSet<>();
        for (int si : targets) {
            int u = pool.stringIndex(si);
            List<Integer> refs = backrefs.get(u);
            if (refs == null) {
                continue;
            }
            boolean only = true;
            for (int r : refs) {
                if (!(pool.tag[r] == TAG_STRING && targetSet.contains(r))) {
                    only = false;
                    break;
                }
            }
            if (only) {
                blank.add(u);
            }
        }
        List<byte[]> tokens = new ArrayList<>(targets.size());
        for (int si : targets) {
            String plain = decodeMUTF8(pool.utf8(pool.stringIndex(si)));
            tokens.add(CondyStrings.seal(plain, fileKey).getBytes(StandardCharsets.US_ASCII));
        }
        int sharedBase = pool.count;
        int bsmBase = pool.bsmEntryCount;
        int perString = targets.size();
        boolean needAttrName = pool.bsmNameIdx < 0;
        int next = sharedBase + SHARED_COUNT + perString * 2 + (needAttrName ? 1 : 0);
        int idxNat = sharedBase + 2;
        int idxMh = sharedBase + 9;
        int uTok0 = sharedBase + SHARED_COUNT;
        int bsmNameIdx = needAttrName ? next - 1 : pool.bsmNameIdx;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(classBytes.length + perString * 160);
            DataOutputStream dos = new DataOutputStream(bos);
            dos.write(classBytes, 0, 8);
            dos.writeShort(next);
            for (int i = 1; i < pool.count; i++) {
                int r = targets.indexOf(i);
                if (r >= 0) {
                    dos.writeByte(TAG_DYNAMIC);
                    dos.writeShort(bsmBase + r);
                    dos.writeShort(idxNat);
                } else if (pool.tag[i] == TAG_UTF8 && blank.contains(i)) {
                    dos.writeByte(TAG_UTF8);
                    int blen = pool.len[i] - 3;
                    dos.writeShort(blen);
                    byte[] fill = new byte[blen];
                    Arrays.fill(fill, (byte) 0x3F);
                    dos.write(fill);
                    Arrays.fill(fill, (byte) 0);
                } else {
                    dos.write(pool.file, pool.start[i], pool.len[i]);
                }
                if (pool.tag[i] == TAG_LONG || pool.tag[i] == TAG_DOUBLE) {
                    i++;
                }
            }
            writeUtf8(dos, HIDDEN_NAME);
            writeUtf8(dos, STRING_DESC);
            writeNameAndType(dos, sharedBase, sharedBase + 1);
            writeUtf8(dos, BSM_CLASS);
            writeUtf8(dos, BSM_METHOD);
            writeUtf8(dos, BSM_DESC);
            writeClass(dos, sharedBase + 3);
            writeNameAndType(dos, sharedBase + 4, sharedBase + 5);
            writeMethodref(dos, sharedBase + 6, sharedBase + 7);
            writeMethodHandle(dos, sharedBase + 8);
            for (int t = 0; t < perString; t++) {
                byte[] tok = tokens.get(t);
                dos.writeByte(TAG_UTF8);
                dos.writeShort(tok.length);
                dos.write(tok);
                dos.writeByte(TAG_STRING);
                dos.writeShort(uTok0 + t * 2);
            }
            if (needAttrName) {
                writeUtf8(dos, BSM_ATTR);
            }
            byte[] newEntries = bsmEntries(uTok0, idxMh, perString);
            dos.write(pool.file, pool.afterPool, pool.classAttrCountPos - pool.afterPool);
            int acount = u2(pool.file, pool.classAttrCountPos);
            dos.writeShort(acount + (pool.bsmRaw != null ? 0 : 1));
            for (int k = 0; k < pool.attrSpans.size(); k++) {
                int[] sp = pool.attrSpans.get(k);
                if (k == pool.bsmSpan) {
                    dos.writeShort(pool.bsmNameIdx);
                    dos.writeInt(2 + (pool.bsmRaw.length - 2) + newEntries.length);
                    dos.writeShort(bsmBase + perString);
                    dos.write(pool.bsmRaw, 2, pool.bsmRaw.length - 2);
                    dos.write(newEntries);
                } else {
                    dos.write(pool.file, sp[0], sp[1]);
                }
            }
            if (pool.bsmRaw == null) {
                dos.writeShort(bsmNameIdx);
                dos.writeInt(2 + newEntries.length);
                dos.writeShort(perString);
                dos.write(newEntries);
            }
            dos.flush();
            return new Result(bos.toByteArray(), perString);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static List<Integer> cpRefs(Pool pool, int i) {
        List<Integer> out = new ArrayList<>(2);
        byte[] f = pool.file;
        int s = pool.start[i];
        switch (pool.tag[i]) {
            case TAG_CLASS:
            case TAG_STRING:
            case 16:
            case 19:
            case 20:
                out.add(u2(f, s + 1));
                break;
            case 9:
            case 10:
            case 11:
            case 12:
                out.add(u2(f, s + 1));
                out.add(u2(f, s + 3));
                break;
            case 15:
                out.add(u2(f, s + 2));
                break;
            case 17:
            case 18:
                out.add(u2(f, s + 3));
                break;
            default:
                break;
        }
        return out;
    }

    private static byte[] bsmEntries(int uTok0, int idxMh, int perString) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(perString * 6);
        DataOutputStream dos = new DataOutputStream(bos);
        for (int t = 0; t < perString; t++) {
            dos.writeShort(idxMh);
            dos.writeShort(1);
            dos.writeShort(uTok0 + t * 2 + 1);
        }
        dos.flush();
        return bos.toByteArray();
    }

    static int u2(byte[] b, int p) {
        return ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF);
    }

    static int u4(byte[] b, int p) {
        return ((b[p] & 0xFF) << 24) | ((b[p + 1] & 0xFF) << 16) | ((b[p + 2] & 0xFF) << 8) | (b[p + 3] & 0xFF);
    }

    static String decodeMUTF8(byte[] b) {
        char[] out = new char[b.length];
        int o = 0;
        int i = 0;
        while (i < b.length) {
            int a = b[i++] & 0xFF;
            if (a < 0x80) {
                out[o++] = (char) a;
            } else if ((a & 0xE0) == 0xC0) {
                if (i >= b.length) {
                    throw new IllegalArgumentException("bad mutf8");
                }
                int c2 = b[i++] & 0xFF;
                if ((c2 & 0xC0) != 0x80) {
                    throw new IllegalArgumentException("bad mutf8");
                }
                out[o++] = (char) (((a & 0x1F) << 6) | (c2 & 0x3F));
            } else if ((a & 0xF0) == 0xE0) {
                if (i + 1 >= b.length) {
                    throw new IllegalArgumentException("bad mutf8");
                }
                int c2 = b[i++] & 0xFF;
                int c3 = b[i++] & 0xFF;
                if ((c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) {
                    throw new IllegalArgumentException("bad mutf8");
                }
                out[o++] = (char) (((a & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F));
            } else {
                throw new IllegalArgumentException("bad mutf8");
            }
        }
        return new String(out, 0, o);
    }

    private static void writeUtf8(DataOutputStream dos, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        dos.writeByte(TAG_UTF8);
        dos.writeShort(b.length);
        dos.write(b);
    }

    private static void writeClass(DataOutputStream dos, int nameIdx) throws IOException {
        dos.writeByte(TAG_CLASS);
        dos.writeShort(nameIdx);
    }

    private static void writeNameAndType(DataOutputStream dos, int nameIdx, int descIdx) throws IOException {
        dos.writeByte(TAG_NAMEANDTYPE);
        dos.writeShort(nameIdx);
        dos.writeShort(descIdx);
    }

    private static void writeMethodref(DataOutputStream dos, int clsIdx, int natIdx) throws IOException {
        dos.writeByte(TAG_METHODREF);
        dos.writeShort(clsIdx);
        dos.writeShort(natIdx);
    }

    private static void writeMethodHandle(DataOutputStream dos, int refIdx) throws IOException {
        dos.writeByte(TAG_METHODHANDLE);
        dos.writeByte(REF_INVOKE_STATIC);
        dos.writeShort(refIdx);
    }

    private static final class Pool {
        byte[] file;
        int count;
        int[] tag;
        int[] start;
        int[] len;
        int afterPool;
        int classAttrCountPos;
        List<int[]> attrSpans = new ArrayList<>();
        int bsmSpan = -1;
        Set<Integer> excluded = new HashSet<>();
        byte[] bsmRaw;
        int bsmNameIdx = -1;
        int bsmEntryCount;

        static Pool parse(byte[] f) {
            Pool p = new Pool();
            p.file = f;
            p.count = u2(f, 8);
            p.tag = new int[p.count];
            p.start = new int[p.count];
            p.len = new int[p.count];
            int pos = 10;
            for (int i = 1; i < p.count; i++) {
                int t = f[pos] & 0xFF;
                p.tag[i] = t;
                p.start[i] = pos;
                int l = entryLen(f, pos, t);
                p.len[i] = l;
                pos += l;
                if (t == TAG_LONG || t == TAG_DOUBLE) {
                    i++;
                }
            }
            p.afterPool = pos;
            pos += 6;
            int icount = u2(f, pos);
            pos += 2 + icount * 2;
            int fcount = u2(f, pos);
            pos += 2;
            for (int k = 0; k < fcount; k++) {
                pos = p.scanFieldConstantValue(f, pos);
            }
            int mcount = u2(f, pos);
            pos += 2;
            for (int k = 0; k < mcount; k++) {
                pos = skipMember(f, pos);
            }
            p.classAttrCountPos = pos;
            int acount = u2(f, pos);
            pos += 2;
            for (int k = 0; k < acount; k++) {
                int astart = pos;
                int nidx = u2(f, pos);
                int alen = u4(f, pos + 2);
                if (p.utf8Equals(nidx, BSM_ATTR)) {
                    p.bsmSpan = p.attrSpans.size();
                    p.bsmNameIdx = nidx;
                    p.bsmRaw = Arrays.copyOfRange(f, pos + 6, pos + 6 + alen);
                    p.harvestExcluded();
                }
                p.attrSpans.add(new int[]{astart, 6 + alen});
                pos += 6 + alen;
            }
            int num = p.bsmRaw != null ? u2(p.bsmRaw, 0) : 0;
            p.bsmEntryCount = num;
            return p;
        }

        int stringIndex(int stringCpIdx) {
            return u2(file, start[stringCpIdx] + 1);
        }

        byte[] utf8(int utf8CpIdx) {
            return Arrays.copyOfRange(file, start[utf8CpIdx] + 3, start[utf8CpIdx] + len[utf8CpIdx]);
        }

        int utf8Len(int utf8CpIdx) {
            return len[utf8CpIdx] - 3;
        }

        boolean utf8Equals(int utf8CpIdx, String ascii) {
            byte[] raw = utf8(utf8CpIdx);
            if (raw.length != ascii.length()) {
                return false;
            }
            for (int i = 0; i < raw.length; i++) {
                if ((raw[i] & 0xFF) != ascii.charAt(i)) {
                    return false;
                }
            }
            return true;
        }

        int scanFieldConstantValue(byte[] f, int pos) {
            int acount = u2(f, pos + 6);
            int q = pos + 8;
            for (int k = 0; k < acount; k++) {
                int nidx = u2(f, q);
                int alen = u4(f, q + 2);
                if (alen == 2 && utf8Equals(nidx, "ConstantValue")) {
                    int cv = u2(f, q + 6);
                    if (cv > 0 && cv < count && tag[cv] == TAG_STRING) {
                        excluded.add(cv);
                    }
                }
                q += 6 + alen;
            }
            return q;
        }

        void harvestExcluded() {
            int num = u2(bsmRaw, 0);
            int off = 2;
            for (int k = 0; k < num; k++) {
                off += 2;
                int nargs = u2(bsmRaw, off);
                off += 2;
                for (int j = 0; j < nargs; j++) {
                    int a = u2(bsmRaw, off);
                    off += 2;
                    if (a > 0 && a < count && tag[a] == TAG_STRING) {
                        excluded.add(a);
                    }
                }
            }
        }

        static int entryLen(byte[] f, int pos, int t) {
            switch (t) {
                case TAG_UTF8:
                    return 3 + u2(f, pos + 1);
                case 3:
                case 4:
                    return 5;
                case TAG_LONG:
                case TAG_DOUBLE:
                    return 9;
                case TAG_CLASS:
                case TAG_STRING:
                case 16:
                case 19:
                case 20:
                    return 3;
                case 9:
                case 10:
                case 11:
                case 12:
                case 17:
                case 18:
                    return 5;
                case 15:
                    return 4;
                default:
                    throw new IllegalArgumentException("bad cp tag " + t);
            }
        }

        static int skipMember(byte[] f, int pos) {
            int acount = u2(f, pos + 6);
            pos += 8;
            for (int k = 0; k < acount; k++) {
                pos += 6 + u4(f, pos + 2);
            }
            return pos;
        }
    }
}
