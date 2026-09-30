#include <jni.h>
#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS) 0x00000000L)
#endif

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

static const unsigned char VAULT_SALT[16] = {
    0xA7, 0x3E, 0x11, 0xC9, 0x5D, 0x82, 0x0F, 0x64,
    0xB1, 0x2A, 0xE8, 0x47, 0x93, 0x0C, 0xD6, 0x78
};

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(const unsigned char* data, int len, char* out, int cap) {
    int required = ((len + 2) / 3) * 4;
    int o = 0;
    int i = 0;
    if (out == NULL || cap < required + 1) {
        return 0;
    }
    while (i + 3 <= len) {
        unsigned int t = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out[o++] = B64[(t >> 18) & 0x3F];
        out[o++] = B64[(t >> 12) & 0x3F];
        out[o++] = B64[(t >> 6) & 0x3F];
        out[o++] = B64[t & 0x3F];
        i += 3;
    }
    if (len - i == 1) {
        unsigned int t = (data[i] << 16);
        out[o++] = B64[(t >> 18) & 0x3F];
        out[o++] = B64[(t >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    } else if (len - i == 2) {
        unsigned int t = (data[i] << 16) | (data[i + 1] << 8);
        out[o++] = B64[(t >> 18) & 0x3F];
        out[o++] = B64[(t >> 12) & 0x3F];
        out[o++] = B64[(t >> 6) & 0x3F];
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char* in, int inLen, unsigned char* out, int cap) {
    int o = 0;
    int i = 0;
    int buffer = 0;
    int bits = 0;
    for (i = 0; i < inLen; i++) {
        char c = in[i];
        int v;
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') {
            continue;
        }
        v = b64_value(c);
        if (v < 0) {
            return -1;
        }
        buffer = (buffer << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) {
                return -1;
            }
            out[o++] = (unsigned char) ((buffer >> bits) & 0xFF);
        }
    }
    return o;
}

static int derive_vault_key(unsigned char* key32) {
    unsigned char secret[32];
    char b64secret[64];
    unsigned char derived[64];
    int b64len;
    int i;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;

    for (i = 0; i < 32; i++) {
        secret[i] = PART_A[i] ^ PART_B[i] ^ PART_C[i];
    }
    b64len = b64_encode(secret, 32, b64secret, sizeof(b64secret));
    SecureZeroMemory(secret, sizeof(secret));
    if (b64len == 0) {
        return 0;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                                         BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != STATUS_SUCCESS) {
        SecureZeroMemory(b64secret, sizeof(b64secret));
        return 0;
    }
    status = BCryptDeriveKeyPBKDF2(hAlg,
        (PUCHAR) b64secret, (ULONG) b64len,
        (PUCHAR) VAULT_SALT, sizeof(VAULT_SALT),
        210000ULL,
        derived, sizeof(derived),
        0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    SecureZeroMemory(b64secret, sizeof(b64secret));

    if (status != STATUS_SUCCESS) {
        SecureZeroMemory(derived, sizeof(derived));
        return 0;
    }
    memcpy(key32, derived, 32);
    SecureZeroMemory(derived, sizeof(derived));
    return 1;
}

static int gcm_decrypt(const unsigned char* key,
                       const unsigned char* iv, ULONG ivLen,
                       const unsigned char* ct, ULONG ctLen,
                       const unsigned char* tag, ULONG tagLen,
                       unsigned char* out) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    ULONG produced = 0;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) {
        return 0;
    }
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR) BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR) key, 32, 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR) iv;
    authInfo.cbNonce = ivLen;
    authInfo.pbTag = (PUCHAR) tag;
    authInfo.cbTag = tagLen;

    status = BCryptDecrypt(hKey,
        (PUCHAR) ct, ctLen,
        &authInfo,
        NULL, 0,
        out, ctLen,
        &produced,
        0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status == STATUS_SUCCESS;
}

JNIEXPORT jstring JNICALL
Java_jdk_internal_misc_PmchStrings_reveal(JNIEnv* env, jclass cls, jstring token) {
    const char* tokenChars;
    jsize tokenLen;
    unsigned char* raw;
    int rawLen;
    unsigned char key[32];
    unsigned char* plain;
    int ctLen;
    jstring result = NULL;

    (void) cls;
    if (token == NULL) {
        return NULL;
    }
    tokenChars = (*env)->GetStringUTFChars(env, token, NULL);
    if (tokenChars == NULL) {
        return NULL;
    }
    tokenLen = (*env)->GetStringUTFLength(env, token);

    raw = (unsigned char*) malloc(tokenLen == 0 ? 1 : (size_t) tokenLen);
    if (raw == NULL) {
        (*env)->ReleaseStringUTFChars(env, token, tokenChars);
        return NULL;
    }
    rawLen = b64_decode(tokenChars, (int) tokenLen, raw, (int) tokenLen);
    (*env)->ReleaseStringUTFChars(env, token, tokenChars);

    if (rawLen < 12 + 16) {
        free(raw);
        return NULL;
    }
    if (!derive_vault_key(key)) {
        SecureZeroMemory(raw, (size_t) rawLen);
        free(raw);
        return NULL;
    }

    ctLen = rawLen - 12 - 16;
    plain = (unsigned char*) malloc((size_t) ctLen + 1);
    if (plain == NULL) {
        SecureZeroMemory(key, sizeof(key));
        SecureZeroMemory(raw, (size_t) rawLen);
        free(raw);
        return NULL;
    }

    if (gcm_decrypt(key, raw, 12, raw + 12, (ULONG) ctLen, raw + 12 + ctLen, 16, plain)) {
        plain[ctLen] = '\0';
        result = (*env)->NewStringUTF(env, (const char*) plain);
    }

    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(plain, (size_t) ctLen + 1);
    SecureZeroMemory(raw, (size_t) rawLen);
    free(plain);
    free(raw);
    return result;
}
