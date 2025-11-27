/**
 * @file encrypted_value.h
 * @brief Encrypted values stored in memory
 *
 * Prevents simple memory patching attacks by encrypting boolean flags
 * and other critical values with random keys and checksums.
 */

#pragma once

#include <cstdint>
#include <random>
#include <cstdlib>

namespace oliviauth {

/**
 * @brief Template for encrypted values in memory
 *
 * Stores values encrypted with a random key + checksum to detect tampering.
 * Makes Cheat Engine and memory editors much harder to use.
 */
template<typename T>
class EncryptedValue {
private:
    uint64_t encrypted_;    // Encrypted value
    uint64_t key_;          // Random XOR key
    uint32_t checksum_;     // Integrity checksum

    /**
     * @brief Generate random encryption key
     */
    static uint64_t random_key() {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        return gen();
    }

    /**
     * @brief Calculate checksum for integrity verification
     */
    static uint32_t calc_checksum(T val, uint64_t key) {
        uint64_t data = static_cast<uint64_t>(val) ^ key;
        return static_cast<uint32_t>((data >> 32) ^ data ^ 0xDEADBEEF);
    }

public:
    /**
     * @brief Constructor with initial value
     */
    EncryptedValue(T initial = T{}) {
        set(initial);
    }

    /**
     * @brief Set new value (re-encrypts with new random key)
     */
    void set(T value) {
        key_ = random_key();
        encrypted_ = static_cast<uint64_t>(value) ^ key_;
        checksum_ = calc_checksum(value, key_);
    }

    /**
     * @brief Get decrypted value (with integrity check)
     */
    T get() const {
        T result = static_cast<T>(encrypted_ ^ key_);

        // Verify integrity
        if (calc_checksum(result, key_) != checksum_) {
            // TAMPERING DETECTED!
            // Instead of crashing immediately (too obvious), corrupt the value
            return T{};  // Return default/false
        }

        return result;
    }

    /**
     * @brief Implicit conversion to T
     */
    operator T() const {
        return get();
    }

    /**
     * @brief Assignment operator
     */
    EncryptedValue& operator=(T value) {
        set(value);
        return *this;
    }

    /**
     * @brief Copy constructor
     */
    EncryptedValue(const EncryptedValue& other)
        : encrypted_(other.encrypted_)
        , key_(other.key_)
        , checksum_(other.checksum_) {
    }

    /**
     * @brief Copy assignment
     */
    EncryptedValue& operator=(const EncryptedValue& other) {
        if (this != &other) {
            encrypted_ = other.encrypted_;
            key_ = other.key_;
            checksum_ = other.checksum_;
        }
        return *this;
    }
};

// Type aliases for common use cases
using EncryptedBool = EncryptedValue<bool>;
using EncryptedInt = EncryptedValue<int>;
using EncryptedInt64 = EncryptedValue<int64_t>;

} // namespace oliviauth
