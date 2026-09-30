#include "precompiled.hpp"
#include "classfile/pmchDecrypt.hpp"

#ifdef _WINDOWS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS) 0x00000000L)
#endif

static const unsigned char PMCH_MAGIC[4] = { 'P', 'M', 'C', 'H' };
static const unsigned char PMCH_VERSION = 1;
static const unsigned char PMCH_VERSION_JARHOOK = 2;
static const unsigned char PMCH_VERSION_SEALED = 3;
static const int PMCH_IV_BYTES = 12;
static const int PMCH_TAG_BYTES = 16;
static const int PMCH_HEADER_BYTES = 4 + 1 + PMCH_IV_BYTES;
static const int PMCH_SEAL_SALT_BYTES = 16;
static const int PMCH_SEAL_SEED_BYTES = 16;
static const int PMCH_SEAL_HEADER_BYTES = 4 + 1 + 16 + 16 + PMCH_IV_BYTES;
static const int PMCH_FILE_KEY_BYTES = 32;
static const unsigned long long PMCH_ITERATIONS = 210000ULL;
static const int PMCH_DERIVED_BYTES = 64;
static const int PMCH_AES_KEY_BYTES = 32;

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

static const unsigned char PMCH_SALT[16] = {
    0x4A, 0x1C, 0xF7, 0x82, 0x30, 0x6B, 0xD5, 0x9E,
    0x07, 0xC4, 0x51, 0xA8, 0x2F, 0xE3, 0x18, 0x7D
};

static const char PMCH_B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int pmch_base64(const unsigned char* data, int len, char* out, int cap) {
    int required = ((len + 2) / 3) * 4;
    if (out == nullptr || cap < required + 1) {
        return 0;
    }
    int o = 0;
    int i = 0;
    while (i + 3 <= len) {
        unsigned int t = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out[o++] = PMCH_B64[(t >> 18) & 0x3F];
        out[o++] = PMCH_B64[(t >> 12) & 0x3F];
        out[o++] = PMCH_B64[(t >> 6) & 0x3F];
        out[o++] = PMCH_B64[t & 0x3F];
        i += 3;
    }
    int rem = len - i;
    if (rem == 1) {
        unsigned int t = (data[i] << 16);
        out[o++] = PMCH_B64[(t >> 18) & 0x3F];
        out[o++] = PMCH_B64[(t >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        unsigned int t = (data[i] << 16) | (data[i + 1] << 8);
        out[o++] = PMCH_B64[(t >> 18) & 0x3F];
        out[o++] = PMCH_B64[(t >> 12) & 0x3F];
        out[o++] = PMCH_B64[(t >> 6) & 0x3F];
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static bool pmch_pbkdf2(const unsigned char* password, unsigned long passwordLen,
                        unsigned char* derived, unsigned long derivedLen) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != STATUS_SUCCESS) {
        return false;
    }
    status = BCryptDeriveKeyPBKDF2(
        hAlg,
        (PUCHAR) password, passwordLen,
        (PUCHAR) PMCH_SALT, sizeof(PMCH_SALT),
        PMCH_ITERATIONS,
        derived, derivedLen,
        0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status == STATUS_SUCCESS;
}

static bool pmch_gcm_decrypt(const unsigned char* key,
                             const unsigned char* iv, unsigned long ivLen,
                             const unsigned char* ciphertext, unsigned long ctLen,
                             const unsigned char* tag, unsigned long tagLen,
                             unsigned char* output) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != STATUS_SUCCESS) {
        return false;
    }
    status = BCryptSetProperty(
        hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR) BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                        (PUCHAR) key, PMCH_AES_KEY_BYTES, 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR) iv;
    authInfo.cbNonce = ivLen;
    authInfo.pbTag = (PUCHAR) tag;
    authInfo.cbTag = tagLen;

    ULONG produced = 0;
    status = BCryptDecrypt(
        hKey,
        (PUCHAR) ciphertext, ctLen,
        &authInfo,
        nullptr, 0,
        output, ctLen,
        &produced,
        0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status == STATUS_SUCCESS;
}

static bool pmch_sha256(const unsigned char* data, unsigned long len,
                        unsigned char out32[32]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status != STATUS_SUCCESS) {
        return false;
    }
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    status = BCryptHashData(hHash, (PUCHAR) data, len, 0);
    if (status == STATUS_SUCCESS) {
        status = BCryptFinishHash(hHash, out32, 32, 0);
    }
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status == STATUS_SUCCESS;
}

static bool pmch_hmac_sha256(const unsigned char* key, unsigned long keyLen,
                             const unsigned char* data, unsigned long dataLen,
                             unsigned char out32[32]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != STATUS_SUCCESS) {
        return false;
    }
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, (PUCHAR) key, keyLen, 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    status = BCryptHashData(hHash, (PUCHAR) data, dataLen, 0);
    if (status == STATUS_SUCCESS) {
        status = BCryptFinishHash(hHash, out32, 32, 0);
    }
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status == STATUS_SUCCESS;
}

static const unsigned long long PMCH_FERMAT_P = 2147483647ULL;
static const unsigned long long PMCH_FNV_OFFSET = 0xCBF29CE484222325ULL;
static const unsigned long long PMCH_FNV_PRIME = 1099511628211ULL;
static const unsigned long long PMCH_GOLDEN = 0x9E3779B97F4A7C15ULL;
static const unsigned long long PMCH_COLLAPSE_CAP = 5000ULL;

static unsigned long long pmch_fnv_feed(unsigned long long h,
                                        const unsigned char* d, unsigned long len) {
    for (unsigned long i = 0; i < len; i++) {
        h ^= (unsigned long long) d[i];
        h *= PMCH_FNV_PRIME;
    }
    return h;
}

static unsigned long long pmch_modpow(unsigned long long base,
                                      unsigned long long exp,
                                      unsigned long long mod) {
    unsigned long long res = 1 % mod;
    unsigned long long b = base % mod;
    while (exp > 0) {
        if (exp & 1ULL) {
            res = (res * b) % mod;
        }
        b = (b * b) % mod;
        exp >>= 1;
    }
    return res;
}

static void pmch_le64(unsigned long long v, unsigned char out[8]) {
    for (int i = 0; i < 8; i++) {
        out[i] = (unsigned char) (v & 0xFFULL);
        v >>= 8;
    }
}

static bool pmch_opaque_digest(const unsigned char salt[16],
                               const unsigned char seed[16],
                               unsigned char out32[32]) {
    unsigned long long h = pmch_fnv_feed(PMCH_FNV_OFFSET, salt, 16);
    h = pmch_fnv_feed(h, seed, 16);

    unsigned long long base = (h % (PMCH_FERMAT_P - 2ULL)) + 2ULL;
    unsigned long long modexp = pmch_modpow(base, PMCH_FERMAT_P - 1ULL, PMCH_FERMAT_P);

    unsigned long long sh = pmch_fnv_feed(PMCH_FNV_OFFSET, seed, 16);
    unsigned long long seedMix = sh & 0xFFFFULL;
    unsigned long long n = ((h & 0xFFFFFFULL) | 1ULL) + seedMix + 1ULL;
    unsigned long long steps = 0;
    unsigned long long accum = PMCH_GOLDEN;
    while (n != 1ULL && steps < PMCH_COLLAPSE_CAP) {
        accum ^= n + PMCH_GOLDEN + (accum << 6) + (accum >> 2);
        if ((n & 1ULL) == 0ULL) {
            n >>= 1;
        } else {
            n = 3ULL * n + 1ULL;
        }
        steps++;
    }

    unsigned char msg[56];
    memcpy(msg, salt, 16);
    memcpy(msg + 16, seed, 16);
    pmch_le64(modexp, msg + 32);
    pmch_le64(steps, msg + 40);
    pmch_le64(accum, msg + 48);
    bool ok = pmch_sha256(msg, sizeof(msg), out32);
    SecureZeroMemory(msg, sizeof(msg));
    return ok;
}

static int pmch_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

struct PmchKeyHolder {
    bool ok;
    unsigned char key[PMCH_AES_KEY_BYTES];

    PmchKeyHolder() {
        ok = false;
        memset(key, 0, sizeof(key));

        char passphrase[512];
        DWORD passLen = GetEnvironmentVariableA("PMCH_PASS", passphrase, sizeof(passphrase));
        if (passLen == 0 || passLen >= sizeof(passphrase)) {
            return;
        }

        unsigned char secret[32];
        for (int i = 0; i < 32; i++) {
            secret[i] = PART_A[i] ^ PART_B[i] ^ PART_C[i];
        }

        char b64[64];
        int b64Len = pmch_base64(secret, 32, b64, sizeof(b64));
        SecureZeroMemory(secret, sizeof(secret));
        if (b64Len == 0) {
            return;
        }

        int materialLen = (int) passLen + b64Len;
        unsigned char* material = (unsigned char*) malloc((size_t) materialLen);
        if (material == nullptr) {
            return;
        }
        memcpy(material, passphrase, passLen);
        memcpy(material + passLen, b64, (size_t) b64Len);
        SecureZeroMemory(passphrase, sizeof(passphrase));
        SecureZeroMemory(b64, sizeof(b64));

        unsigned char derived[PMCH_DERIVED_BYTES];
        bool derivedOk = pmch_pbkdf2(material, (unsigned long) materialLen,
                                     derived, (unsigned long) PMCH_DERIVED_BYTES);
        SecureZeroMemory(material, (size_t) materialLen);
        free(material);

        if (derivedOk) {
            memcpy(key, derived, PMCH_AES_KEY_BYTES);
            ok = true;
        }
        SecureZeroMemory(derived, sizeof(derived));
    }
};

static bool pmch_get_key(unsigned char out[PMCH_AES_KEY_BYTES]) {
    static PmchKeyHolder holder;
    if (!holder.ok) {
        return false;
    }
    memcpy(out, holder.key, PMCH_AES_KEY_BYTES);
    return true;
}

struct PmchSealHolder {
    bool ok;
    unsigned char key[PMCH_FILE_KEY_BYTES];

    PmchSealHolder() {
        ok = false;
        memset(key, 0, sizeof(key));
        char hex[128];
        DWORD hexLen = GetEnvironmentVariableA("PMCH_SEAL", hex, sizeof(hex));
        if (hexLen != 64) {
            SecureZeroMemory(hex, sizeof(hex));
            return;
        }
        unsigned char raw[PMCH_FILE_KEY_BYTES];
        for (int i = 0; i < PMCH_FILE_KEY_BYTES; i++) {
            int hi = pmch_hexval(hex[2 * i]);
            int lo = pmch_hexval(hex[2 * i + 1]);
            if (hi < 0 || lo < 0) {
                SecureZeroMemory(hex, sizeof(hex));
                SecureZeroMemory(raw, sizeof(raw));
                return;
            }
            raw[i] = (unsigned char) ((hi << 4) | lo);
        }
        SecureZeroMemory(hex, sizeof(hex));
        memcpy(key, raw, sizeof(key));
        SecureZeroMemory(raw, sizeof(raw));
        ok = true;
    }
};

static bool pmch_get_seal_key(unsigned char out[PMCH_FILE_KEY_BYTES]) {
    static PmchSealHolder holder;
    if (!holder.ok) {
        return false;
    }
    memcpy(out, holder.key, PMCH_FILE_KEY_BYTES);
    return true;
}

static bool pmch_try_decrypt_sealed(const unsigned char* in, int in_len,
                                    unsigned char** out, int* out_len) {
    if (in_len < PMCH_SEAL_HEADER_BYTES + PMCH_TAG_BYTES) {
        return false;
    }
    unsigned char fileKey[PMCH_FILE_KEY_BYTES];
    if (!pmch_get_seal_key(fileKey)) {
        return false;
    }

    const unsigned char* salt = in + 5;
    const unsigned char* seed = in + 5 + PMCH_SEAL_SALT_BYTES;
    const unsigned char* iv = in + 5 + PMCH_SEAL_SALT_BYTES + PMCH_SEAL_SEED_BYTES;
    const unsigned char* ciphertext = in + PMCH_SEAL_HEADER_BYTES;
    int ctLen = in_len - PMCH_SEAL_HEADER_BYTES - PMCH_TAG_BYTES;
    if (ctLen < 0) {
        SecureZeroMemory(fileKey, sizeof(fileKey));
        return false;
    }
    const unsigned char* tag = in + PMCH_SEAL_HEADER_BYTES + ctLen;

    unsigned char digest[32];
    if (!pmch_opaque_digest(salt, seed, digest)) {
        SecureZeroMemory(fileKey, sizeof(fileKey));
        return false;
    }
    unsigned char kmix[PMCH_AES_KEY_BYTES];
    if (!pmch_hmac_sha256(fileKey, sizeof(fileKey), digest, sizeof(digest), kmix)) {
        SecureZeroMemory(fileKey, sizeof(fileKey));
        SecureZeroMemory(digest, sizeof(digest));
        return false;
    }
    SecureZeroMemory(fileKey, sizeof(fileKey));
    SecureZeroMemory(digest, sizeof(digest));

    unsigned char* plaintext = (unsigned char*) malloc(ctLen == 0 ? 1 : (size_t) ctLen);
    if (plaintext == nullptr) {
        SecureZeroMemory(kmix, sizeof(kmix));
        return false;
    }
    bool ok = pmch_gcm_decrypt(kmix, iv, PMCH_IV_BYTES,
                               ciphertext, (unsigned long) ctLen,
                               tag, PMCH_TAG_BYTES,
                               plaintext);
    SecureZeroMemory(kmix, sizeof(kmix));
    if (!ok) {
        SecureZeroMemory(plaintext, ctLen == 0 ? 1 : (size_t) ctLen);
        free(plaintext);
        return false;
    }
    *out = plaintext;
    *out_len = ctLen;
    return true;
}

extern "C" bool pmch_try_decrypt(const char* class_name,
                                 const unsigned char* in, int in_len,
                                 unsigned char** out, int* out_len) {
    if (in == nullptr || out == nullptr || out_len == nullptr) {
        return false;
    }
    if (in_len < PMCH_HEADER_BYTES + PMCH_TAG_BYTES) {
        return false;
    }
    if (memcmp(in, PMCH_MAGIC, 4) != 0) {
        return false;
    }
    if (in[4] == PMCH_VERSION_SEALED) {
        return pmch_try_decrypt_sealed(in, in_len, out, out_len);
    }
    if (in[4] != PMCH_VERSION && in[4] != PMCH_VERSION_JARHOOK) {
        return false;
    }

    unsigned char master[PMCH_AES_KEY_BYTES];
    if (!pmch_get_key(master)) {
        return false;
    }

    unsigned char key[PMCH_AES_KEY_BYTES];
    if (in[4] == PMCH_VERSION_JARHOOK) {
        if (class_name == nullptr) {
            SecureZeroMemory(master, sizeof(master));
            return false;
        }
        bool keyOk = pmch_hmac_sha256(master, PMCH_AES_KEY_BYTES,
                                      (const unsigned char*) class_name,
                                      (unsigned long) strlen(class_name),
                                      key);
        SecureZeroMemory(master, sizeof(master));
        if (!keyOk) {
            return false;
        }
    } else {
        memcpy(key, master, PMCH_AES_KEY_BYTES);
        SecureZeroMemory(master, sizeof(master));
    }

    const unsigned char* iv = in + 5;
    const unsigned char* ciphertext = in + PMCH_HEADER_BYTES;
    int ctLen = in_len - PMCH_HEADER_BYTES - PMCH_TAG_BYTES;
    if (ctLen < 0) {
        SecureZeroMemory(key, sizeof(key));
        return false;
    }
    const unsigned char* tag = in + PMCH_HEADER_BYTES + ctLen;

    unsigned char* plaintext = (unsigned char*) malloc(ctLen == 0 ? 1 : (size_t) ctLen);
    if (plaintext == nullptr) {
        SecureZeroMemory(key, sizeof(key));
        return false;
    }

    bool ok = pmch_gcm_decrypt(key, iv, PMCH_IV_BYTES,
                               ciphertext, (unsigned long) ctLen,
                               tag, PMCH_TAG_BYTES,
                               plaintext);
    SecureZeroMemory(key, sizeof(key));

    if (!ok) {
        SecureZeroMemory(plaintext, ctLen == 0 ? 1 : (size_t) ctLen);
        free(plaintext);
        return false;
    }

    *out = plaintext;
    *out_len = ctLen;
    return true;
}

extern "C" void pmch_free(unsigned char* p) {
    if (p != nullptr) {
        free(p);
    }
}

#else

extern "C" bool pmch_try_decrypt(const char*, const unsigned char*, int, unsigned char**, int*) {
    return false;
}

extern "C" void pmch_free(unsigned char*) {
}

#endif
