#include <jni.h>
#include <windows.h>
#include <bcrypt.h>
#include <winternl.h>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS) 0x00000000L)
#endif

static const unsigned char CORE_KEY[32] = {
    0x5C, 0xE1, 0x93, 0x2A, 0x74, 0xB8, 0x0D, 0xF6,
    0x41, 0x9A, 0x27, 0xCE, 0x63, 0x1F, 0xA5, 0x88,
    0x30, 0xDB, 0x4C, 0x7E, 0x12, 0x96, 0xE3, 0x58,
    0xAF, 0x02, 0x6D, 0xB4, 0x39, 0xC1, 0x7A, 0xE9
};

static const unsigned char PART_A[32] = {
    0x9F, 0x11, 0x4C, 0xA2, 0x03, 0xE8, 0x77, 0x5B,
    0x2D, 0xC0, 0x64, 0x91, 0xBA, 0x38, 0x0F, 0xD7,
    0x46, 0xE1, 0x82, 0x59, 0x1C, 0xAF, 0x73, 0x6A,
    0xD4, 0x08, 0x95, 0x3B, 0xCE, 0x27, 0x50, 0xB9
};

static const unsigned char PART_B[32] = {
    0x31, 0x7A, 0xE5, 0x0C, 0x88, 0x4F, 0x1D, 0xC6,
    0x93, 0x2A, 0xB7, 0x60, 0x05, 0xD9, 0x4E, 0x8B,
    0x12, 0xF3, 0x6C, 0xA5, 0x39, 0x80, 0xE7, 0x1E,
    0x57, 0xCB, 0x24, 0x9D, 0x70, 0xB2, 0x4A, 0x03
};

static const unsigned char PART_C[32] = {
    0x6D, 0x2C, 0xF1, 0x58, 0x94, 0x0B, 0xA6, 0x3F,
    0xE2, 0x79, 0x10, 0xCD, 0x66, 0x87, 0x3A, 0xF4,
    0x5B, 0x0E, 0xD1, 0x28, 0xB5, 0x4C, 0x99, 0x62,
    0x07, 0xEA, 0x83, 0x3E, 0xC1, 0x74, 0x1F, 0xA8
};

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(const unsigned char* data, int len, char* out) {
    int o = 0, i = 0;
    while (i + 3 <= len) {
        unsigned int t = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out[o++] = B64[(t >> 18) & 0x3F]; out[o++] = B64[(t >> 12) & 0x3F];
        out[o++] = B64[(t >> 6) & 0x3F]; out[o++] = B64[t & 0x3F];
        i += 3;
    }
    int rem = len - i;
    if (rem == 1) {
        unsigned int t = (data[i] << 16);
        out[o++] = B64[(t >> 18) & 0x3F]; out[o++] = B64[(t >> 12) & 0x3F];
        out[o++] = '='; out[o++] = '=';
    } else if (rem == 2) {
        unsigned int t = (data[i] << 16) | (data[i + 1] << 8);
        out[o++] = B64[(t >> 18) & 0x3F]; out[o++] = B64[(t >> 12) & 0x3F];
        out[o++] = B64[(t >> 6) & 0x3F]; out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char* in, int inLen, unsigned char* out) {
    int o = 0, buffer = 0, bits = 0;
    for (int i = 0; i < inLen; i++) {
        char c = in[i];
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        int v = b64_val(c);
        if (v < 0) return -1;
        buffer = (buffer << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (unsigned char) ((buffer >> bits) & 0xFF); }
    }
    return o;
}

static bool gcm_encrypt(const unsigned char* pt, int ptLen,
                        const unsigned char* iv, unsigned char* ct, unsigned char* tag) {
    BCRYPT_ALG_HANDLE hAlg = nullptr; BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) return false;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR) BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR) CORE_KEY, 32, 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return false;
    }
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = (PUCHAR) iv; ai.cbNonce = 12; ai.pbTag = tag; ai.cbTag = 16;
    ULONG done = 0;
    NTSTATUS s = BCryptEncrypt(hKey, (PUCHAR) pt, ptLen, &ai, nullptr, 0, ct, ptLen, &done, 0);
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    return s == STATUS_SUCCESS;
}

static bool gcm_decrypt(const unsigned char* ct, int ctLen,
                        const unsigned char* iv, const unsigned char* tag, unsigned char* pt) {
    BCRYPT_ALG_HANDLE hAlg = nullptr; BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) return false;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR) BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR) CORE_KEY, 32, 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return false;
    }
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = (PUCHAR) iv; ai.cbNonce = 12; ai.pbTag = (PUCHAR) tag; ai.cbTag = 16;
    ULONG done = 0;
    NTSTATUS s = BCryptDecrypt(hKey, (PUCHAR) ct, ctLen, &ai, nullptr, 0, pt, ctLen, &done, 0);
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    return s == STATUS_SUCCESS;
}

static bool detect_debugger() {
    if (IsDebuggerPresent()) return true;
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) return true;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG len = 0;
    NTSTATUS st = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &len);
    if (st == STATUS_SUCCESS && pbi.PebBaseAddress != nullptr) {
        unsigned char being = *((unsigned char*) pbi.PebBaseAddress + 2);
        if (being != 0) return true;
    }
    return false;
}

// --- PMCH key-source exports (loaded by the custom jvm.dll via PMCH_CORE) ---
// jvm.dll derives the jarhook master key as PBKDF2(passphrase || base64(secret)).
// Keeping the secret bytes here (not in jvm.dll) lets this small DLL be hardened
// (VMProtect/Themida) independently of the 14 MB VM.
//
// Integrity gate: before handing out the secret, we SHA-256 the jvm.dll that is
// actually loaded in this process and compare it to the hash of the build we
// shipped. A swapped (vanilla) or patched (class-dumping) jvm.dll changes the
// hash -> no secret -> classes never decrypt. So tampering with the VM is the
// FIRST barrier, not a bypass. Keep EXPECTED_JVM_SHA256 in sync via
// scripts\set-jvm-hash.ps1 after every jvm.dll rebuild, and harden this DLL
// (VMProtect) so the check itself cannot be trivially NOP'd.

static const unsigned char EXPECTED_JVM_SHA256[32] = {
    0x09, 0xCC, 0x6D, 0xC0, 0x5C, 0x01, 0xB4, 0x75,
    0x72, 0xC0, 0x57, 0xC3, 0x27, 0x85, 0x08, 0x25,
    0x47, 0xEB, 0x94, 0xF9, 0x5E, 0xF1, 0x6A, 0x1B,
    0x51, 0xF8, 0xAD, 0xE1, 0xA2, 0x35, 0x4A, 0x5C
};

static bool sha256_file(const char* path, unsigned char out32[32]) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == STATUS_SUCCESS &&
        BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == STATUS_SUCCESS) {
        unsigned char buf[65536];
        DWORD rd = 0;
        ok = true;
        while (ReadFile(h, buf, sizeof(buf), &rd, nullptr) && rd > 0) {
            if (BCryptHashData(hHash, buf, rd, 0) != STATUS_SUCCESS) { ok = false; break; }
        }
        SecureZeroMemory(buf, sizeof(buf));
        if (ok && BCryptFinishHash(hHash, out32, 32, 0) != STATUS_SUCCESS) {
            ok = false;
        }
    }
    if (hHash != nullptr) BCryptDestroyHash(hHash);
    if (hAlg != nullptr) BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(h);
    return ok;
}

static bool verify_jvm() {
    HMODULE jvm = GetModuleHandleA("jvm.dll");
    if (jvm == nullptr) {
        return false;
    }
    char path[1024];
    DWORD n = GetModuleFileNameA(jvm, path, sizeof(path));
    if (n == 0 || n >= sizeof(path)) {
        return false;
    }
    unsigned char digest[32];
    if (!sha256_file(path, digest)) {
        return false;
    }
    bool match = memcmp(digest, EXPECTED_JVM_SHA256, 32) == 0;
    SecureZeroMemory(digest, sizeof(digest));
    return match;
}

extern "C" __declspec(dllexport) int sgx_resolve(char* out, int cap) {
    if (out == nullptr || cap <= 0) {
        return 0;
    }
    DWORD n = GetEnvironmentVariableA("PMCH_PASS", out, (DWORD) cap);
    if (n == 0 || n >= (DWORD) cap) {
        return 0;
    }
    return (int) n;
}

extern "C" __declspec(dllexport) int sgx_secret(unsigned char* out, int cap) {
    if (out == nullptr || cap < 32) {
        return 0;
    }
    if (!verify_jvm()) {
        return 0;
    }
    for (int i = 0; i < 32; i++) {
        out[i] = (unsigned char) (PART_A[i] ^ PART_B[i] ^ PART_C[i]);
    }
    return 32;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_protectedclient_nativecore_NativeCore_antiDebug(JNIEnv* env, jclass cls) {
    (void) env; (void) cls;
    return detect_debugger() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_protectedclient_nativecore_NativeCore_secretTransform(JNIEnv* env, jclass cls, jlong input) {
    (void) env; (void) cls;
    unsigned long long v = (unsigned long long) input;
    v ^= 0x9E3779B97F4A7C15ULL;
    v *= 0xBF58476D1CE4E5B9ULL;
    v ^= v >> 27;
    v *= 0x94D049BB133111EBULL;
    v ^= v >> 31;
    v += 0xA0761D6478BD642FULL;
    v ^= v >> 33;
    return (jlong) v;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_protectedclient_nativecore_NativeCore_issueLicense(JNIEnv* env, jclass cls, jstring subject) {
    (void) cls;
    if (subject == nullptr) return nullptr;
    const char* subj = env->GetStringUTFChars(subject, nullptr);
    if (subj == nullptr) return nullptr;
    int subjLen = (int) env->GetStringUTFLength(subject);

    unsigned char iv[12];
    BCryptGenRandom(nullptr, iv, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    unsigned char* ct = (unsigned char*) malloc(subjLen == 0 ? 1 : subjLen);
    unsigned char tag[16];
    jstring result = nullptr;
    if (ct != nullptr && gcm_encrypt((const unsigned char*) subj, subjLen, iv, ct, tag)) {
        int blobLen = 12 + subjLen + 16;
        unsigned char* blob = (unsigned char*) malloc(blobLen);
        memcpy(blob, iv, 12);
        memcpy(blob + 12, ct, subjLen);
        memcpy(blob + 12 + subjLen, tag, 16);
        char* out = (char*) malloc(((blobLen + 2) / 3) * 4 + 1);
        b64_encode(blob, blobLen, out);
        result = env->NewStringUTF(out);
        free(blob); free(out);
    }
    if (ct != nullptr) free(ct);
    env->ReleaseStringUTFChars(subject, subj);
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_protectedclient_nativecore_NativeCore_verifyLicense(JNIEnv* env, jclass cls, jstring token) {
    (void) cls;
    if (token == nullptr) return nullptr;
    const char* tk = env->GetStringUTFChars(token, nullptr);
    if (tk == nullptr) return nullptr;
    int tkLen = (int) env->GetStringUTFLength(token);

    unsigned char* raw = (unsigned char*) malloc(tkLen == 0 ? 1 : tkLen);
    jstring result = nullptr;
    int rawLen = b64_decode(tk, tkLen, raw);
    env->ReleaseStringUTFChars(token, tk);

    if (rawLen >= 12 + 16) {
        int ctLen = rawLen - 12 - 16;
        unsigned char* pt = (unsigned char*) malloc(ctLen + 1);
        if (pt != nullptr && gcm_decrypt(raw + 12, ctLen, raw, raw + 12 + ctLen, pt)) {
            pt[ctLen] = '\0';
            result = env->NewStringUTF((const char*) pt);
        }
        if (pt != nullptr) { SecureZeroMemory(pt, ctLen + 1); free(pt); }
    }
    if (raw != nullptr) free(raw);
    return result;
}
