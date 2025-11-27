/**
 * @file xor.h
 * @brief Compile-time string encryption
 *
 * This file provides compile-time XOR encryption for string literals
 * to prevent static analysis tools from extracting sensitive strings.
 *
 * Copy this file to your project and use: RXor("your string here")
 *
 * Example:
 *   const char* api_key = RXor("your_secret_key");
 *   const char* endpoint = RXor("https://api.example.com");
 */

#ifndef XOR_HPP
#define XOR_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>

template <typename T>
struct remove_const {
    typedef T type;
};

template <typename T>
struct remove_const<const T> {
    typedef T type;
};

template <typename T>
struct remove_reference {
    typedef T type;
};

template <typename T>
struct remove_reference<T&> {
    typedef T type;
};

template <typename T>
struct remove_cv_ref {
    typedef typename remove_const<typename remove_reference<T>::type>::type type;
};

// Secure buffer clearing - prevents compiler from optimizing away
inline void clearBuffer(char* buffer, size_t size) {
    volatile char* ptr = buffer;
    while (size--) {
        *ptr++ = 0;
    }
}

inline void clearBuffer(wchar_t* buffer, size_t size) {
    volatile wchar_t* ptr = buffer;
    while (size--) {
        *ptr++ = 0;
    }
}

// Compile-time seed generation from __TIME__ and __DATE__
// This ensures each build has unique encryption keys
constexpr int convertTimeToSeconds(const char* time) {
    return ((time[0] - '0') * 10 + (time[1] - '0')) * 3600 +
           ((time[3] - '0') * 10 + (time[4] - '0')) * 60 +
           ((time[6] - '0') * 10 + (time[7] - '0'));
}

constexpr int convertDateToNumber(const char* date) {
    int month = ((date[0] - 'A') ^ (date[1] - 'A') ^ (date[2] - 'A')) & 0xFF;
    int day = ((date[4] >= '0' && date[4] <= '9' ? date[4] - '0' : 0) * 10 +
               (date[5] - '0')) & 0xFF;
    int year = ((date[7] - '0') * 1000 + (date[8] - '0') * 100 +
                (date[9] - '0') * 10 + (date[10] - '0')) & 0xFFFF;
    return (month ^ day ^ year);
}

constexpr unsigned char generateComplexSeed() {
    int timeSeed = convertTimeToSeconds(__TIME__) % 256;
    int dateSeed = convertDateToNumber(__DATE__) % 256;
    unsigned char combinedSeed = static_cast<unsigned char>((timeSeed ^ dateSeed) & 0xFF);
    combinedSeed = ((combinedSeed << 3) | (combinedSeed >> 5)) ^ 0xA5;
    return combinedSeed;
}

constexpr unsigned char XOR_SEED = generateComplexSeed();

constexpr uint64_t generateLargeSeed() {
    uint64_t timeSeed = static_cast<uint64_t>(convertTimeToSeconds(__TIME__));
    uint64_t dateSeed = static_cast<uint64_t>(convertDateToNumber(__DATE__));
    uint64_t combinedSeed = (timeSeed << 32) | dateSeed;
    combinedSeed = ((combinedSeed << 13) | (combinedSeed >> 19)) ^ (XOR_SEED ^ 100);
    return combinedSeed;
}

constexpr uint64_t LARGE_XOR_SEED = generateLargeSeed();
constexpr unsigned char ROR_VALUE = (XOR_SEED % 4) + 1;

#ifdef _MSC_VER
#pragma optimize("", off)
#endif

constexpr unsigned char applyXOR(uint64_t b, unsigned char c, unsigned char seed) {
    return c ^ seed ^ static_cast<unsigned char>(b & 0xFF);
}

#define APPLY_ROR(c, shift) (((c) >> (shift)) | ((c) << (8 - (shift))))
#define APPLY_ROL(c, shift) (((c) << (shift)) | ((c) >> (8 - (shift))))

#define ENCRYPT_CHAR(b, c, seed) \
    APPLY_ROR(applyXOR((b), (c), static_cast<unsigned char>(seed)), ROR_VALUE)

template <typename CharT, size_t N>
struct EncryptedStringT {
    CharT encrypted_chars[N - 1];

    constexpr EncryptedStringT(const CharT(&str)[N]) : encrypted_chars{} {
        for (size_t i = 0; i < N - 1; ++i) {
            encrypted_chars[i] = static_cast<CharT>(
                ENCRYPT_CHAR(LARGE_XOR_SEED,
                             static_cast<unsigned char>(str[i]),
                             XOR_SEED));
        }
    }

    void decrypt(CharT* buffer) const {
        for (size_t i = 0; i < N - 1; ++i) {
            unsigned char decrypted_char = static_cast<unsigned char>(encrypted_chars[i]);
            decrypted_char = APPLY_ROL(decrypted_char, ROR_VALUE);
            buffer[i] = static_cast<CharT>(applyXOR(LARGE_XOR_SEED, decrypted_char, XOR_SEED));
        }
        buffer[N - 1] = static_cast<CharT>(0);
    }
};

#ifdef _MSC_VER
#pragma optimize("", on)
#endif

template <typename CharT, size_t N>
class DecryptedBuffer {
public:
    CharT* buffer;

    DecryptedBuffer(const EncryptedStringT<CharT, N>& encrypted) {
        buffer = static_cast<CharT*>(malloc(N * sizeof(CharT)));
        if (buffer) {
            encrypted.decrypt(buffer);
        }
    }

    ~DecryptedBuffer() {
        if (buffer) {
            clearBuffer(buffer, N);
            free(buffer);
        }
    }

    const CharT* get() const {
        return buffer;
    }

    // Prevent copying
    DecryptedBuffer(const DecryptedBuffer&) = delete;
    DecryptedBuffer& operator=(const DecryptedBuffer&) = delete;
};

// Main macro for XOR string encryption
// Usage: RXor("your string") returns const char*
#define RXor(str) ([]() -> const auto* { \
    using CharT = typename remove_cv_ref<decltype(str[0])>::type; \
    static constexpr EncryptedStringT<CharT, sizeof(str)/sizeof(str[0])> encrypted{str}; \
    static DecryptedBuffer<CharT, sizeof(str)/sizeof(str[0])> buffer{encrypted}; \
    return buffer.get(); \
}())

// Wide string version
#define RXorW(str) RXor(str)

#endif // XOR_HPP
