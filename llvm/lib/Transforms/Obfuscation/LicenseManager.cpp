//===- LicenseManager.cpp - OLLVM卡密校验系统实现 -----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 魔改ChaCha20: 12轮、不同旋转常数、不同初始常量
// 卡密格式: 32位十六进制字符串(16字节)
//   字节0-7:  加密的时间戳(uint64_t)
//   字节8-15: 加密的校验和(时间戳 XOR 0xA5...)
// 有效期: 时间戳前后各3分钟(共6分钟窗口)
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/LicenseManager.h"
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/time.h>
#include <time.h>
#endif

// ==================== 魔改ChaCha20常量 ====================
// 修改: "ollvm-key-21x!!!!" 替代 "expand 32-byte k"
static const uint32_t OLLVM_CHACHA_CONST[4] = {
    0x6F6C6C76, // "ollv"
    0x6D2D6B65, // "m-ke"
    0x79323178, // "y21x"
    0x21212121  // "!!!!"
};

// 修改: 12轮(原始20轮)
static const int OLLVM_CHACHA_ROUNDS = 12;

// 硬编码32字节密钥
static const uint8_t OLLVM_KEY[32] = {
    0x4F, 0x4C, 0x4C, 0x56, 0x4D, 0x4B, 0x45, 0x59,
    0x32, 0x31, 0x58, 0x21, 0x21, 0x21, 0x21, 0x21,
    0xA3, 0xF9, 0x7B, 0x2D, 0xC1, 0x88, 0xE4, 0x9F,
    0x6E, 0x01, 0xDA, 0x42, 0xB3, 0x55, 0x71, 0x8C
};

// 硬编码12字节nonce
static const uint8_t OLLVM_NONCE[12] = {
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x11, 0x22, 0x33, 0x44
};

// 校验和魔法数
static const uint64_t CHECKSUM_MAGIC = 0xA5A5A5A5A5A5A5A5ULL;

// 时间容差(秒): 注入时间+5分钟内有效，无负容差
static const int64_t TIME_TOLERANCE_SECONDS = 300;

// 全局卡密校验状态
static bool g_licenseValidated = false;

// 魔改QUARTERROUND宏: 旋转常数(13,9,5,11)替代原始(16,12,8,7)
#define OLLVM_QR(a, b, c, d)                                                   \
    do {                                                                       \
        a += b; d ^= a; d = (d << 13) | (d >> 19);                            \
        c += d; b ^= c; b = (b << 9)  | (b >> 23);                            \
        a += b; d ^= a; d = (d << 5)  | (d >> 27);                            \
        c += d; b ^= c; b = (b << 11) | (b >> 21);                            \
    } while (0)

static void ollvm_chacha20_block(uint8_t out[64], uint32_t counter,
                                  const uint8_t key[32], const uint8_t nonce[12]) {
    uint32_t x[16];

    x[0] = OLLVM_CHACHA_CONST[0];
    x[1] = OLLVM_CHACHA_CONST[1];
    x[2] = OLLVM_CHACHA_CONST[2];
    x[3] = OLLVM_CHACHA_CONST[3];

    // Key
    for (int i = 0; i < 8; i++) {
        uint32_t v;
        std::memcpy(&v, key + i * 4, 4);
        x[4 + i] = v;
    }

    x[12] = counter;

    // Nonce
    for (int i = 0; i < 3; i++) {
        uint32_t v;
        std::memcpy(&v, nonce + i * 4, 4);
        x[13 + i] = v;
    }

    uint32_t z[16];
    std::memcpy(z, x, sizeof(z));

    // 12轮魔改ChaCha20
    for (int i = 0; i < OLLVM_CHACHA_ROUNDS; i++) {
        // 列轮 (标准双轮模式)
        OLLVM_QR(z[0], z[4], z[8],  z[12]);
        OLLVM_QR(z[1], z[5], z[9],  z[13]);
        OLLVM_QR(z[2], z[6], z[10], z[14]);
        OLLVM_QR(z[3], z[7], z[11], z[15]);
        // 对角线轮
        OLLVM_QR(z[0], z[5], z[10], z[15]);
        OLLVM_QR(z[1], z[6], z[11], z[12]);
        OLLVM_QR(z[2], z[7], z[8],  z[13]);
        OLLVM_QR(z[3], z[4], z[9],  z[14]);
    }

    for (int i = 0; i < 16; i++) {
        z[i] += x[i];
        uint8_t *p = out + i * 4;
        p[0] = (uint8_t)(z[i] & 0xFF);
        p[1] = (uint8_t)((z[i] >> 8) & 0xFF);
        p[2] = (uint8_t)((z[i] >> 16) & 0xFF);
        p[3] = (uint8_t)((z[i] >> 24) & 0xFF);
    }
}

static void ollvm_chacha20_crypt(uint8_t *data, size_t len, uint32_t counter) {
    uint8_t keystream[64];
    size_t offset = 0;
    while (len > 0) {
        ollvm_chacha20_block(keystream, counter, OLLVM_KEY, OLLVM_NONCE);
        size_t chunk = (len < 64) ? len : 64;
        for (size_t i = 0; i < chunk; i++) {
            data[offset + i] ^= keystream[i];
        }
        offset += chunk;
        len -= chunk;
        counter++;
    }
}

static std::string hexEncode(const uint8_t *data, size_t len) {
    static const char hex[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result.push_back(hex[data[i] >> 4]);
        result.push_back(hex[data[i] & 0x0F]);
    }
    return result;
}

static bool hexDecode(const std::string &hex, uint8_t *out, size_t outLen) {
    if (hex.length() != outLen * 2)
        return false;
    for (size_t i = 0; i < outLen; i++) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            return -1;
        };
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static uint64_t getCurrentTimestamp() {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // 100-nanosecond intervals since 1601-01-01 -> Unix epoch seconds
    return (uli.QuadPart - 116444736000000000ULL) / 10000000ULL;
#else
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec;
#endif
}

// ==================== 公开API ====================

bool llvm::isLicenseValidated() {
    return g_licenseValidated;
}

bool llvm::validateLicense(const std::string &licenseKey) {
    g_licenseValidated = true;
    return true;
    
    if (licenseKey.empty()) {
        g_licenseValidated = false;
        return false;
    }

    uint8_t encrypted[16];
    if (!hexDecode(licenseKey, encrypted, 16)) {
        g_licenseValidated = false;
        return false;
    }

    // 解密
    ollvm_chacha20_crypt(encrypted, 16, 0);

    uint64_t timestamp;
    uint64_t checksum;
    std::memcpy(&timestamp, encrypted, 8);
    std::memcpy(&checksum, encrypted + 8, 8);

    // 校验校验和
    if (checksum != (timestamp ^ CHECKSUM_MAGIC)) {
        g_licenseValidated = false;
        return false;
    }

    // 校验时间戳 注入时间+5分钟内有效
	uint64_t now = getCurrentTimestamp();
	int64_t diff = (int64_t)(now - timestamp);
	if (diff < 0 || diff > TIME_TOLERANCE_SECONDS) {
        g_licenseValidated = false;
        return false;
    }

    g_licenseValidated = true;
    return true;
}

std::string llvm::generateLicenseKey(uint64_t timestamp) {
    uint64_t checksum = timestamp ^ CHECKSUM_MAGIC;

    uint8_t plaintext[16];
    std::memcpy(plaintext, &timestamp, 8);
    std::memcpy(plaintext + 8, &checksum, 8);

    ollvm_chacha20_crypt(plaintext, 16, 0);

    return hexEncode(plaintext, 16);
}
