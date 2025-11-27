/**
 * @file crypto.h
 * @brief Internal cryptographic functions for Olivia Auth
 *
 * DO NOT include this file directly. Use oliviauth.h instead.
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace oliviauth {
namespace crypto {

// ============================================================================
// INTERNAL CONSTANTS (prefixed to avoid collision with public header)
// ============================================================================

namespace internal {
constexpr size_t RSA_KEY_SIZE = 2048;
constexpr size_t RSA_CIPHERTEXT_SIZE = 256;  // 2048 bits / 8
constexpr size_t AES_KEY_SIZE = 32;          // 256 bits
constexpr size_t AES_NONCE_SIZE = 12;        // 96 bits (GCM standard)
constexpr size_t AES_TAG_SIZE = 16;          // 128 bits
} // namespace internal

// ============================================================================
// RSA KEY MANAGEMENT
// ============================================================================

/**
 * @brief Opaque RSA key handle
 */
struct RSAKeyPair;

/**
 * @brief Generate RSA-2048 key pair
 * @return Pointer to key pair (must be freed with free_keypair)
 */
RSAKeyPair* generate_keypair();

/**
 * @brief Free RSA key pair
 */
void free_keypair(RSAKeyPair* keypair);

/**
 * @brief Get public key as PEM string
 */
std::string get_public_key_pem(const RSAKeyPair* keypair);

/**
 * @brief Get public key as bytes (DER format)
 */
std::vector<uint8_t> get_public_key_bytes(const RSAKeyPair* keypair);

/**
 * @brief Load public key from PEM string
 */
RSAKeyPair* load_public_key_pem(const std::string& pem);

/**
 * @brief Load public key from Base64 encoded bytes
 */
RSAKeyPair* load_public_key_base64(const std::string& base64_key);

// ============================================================================
// RSA ENCRYPTION
// ============================================================================

/**
 * @brief Encrypt data with RSA public key (OAEP padding)
 * @param data Data to encrypt (max 214 bytes for 2048-bit key with OAEP-SHA256)
 * @param public_key Public key to encrypt with
 * @return Encrypted data (256 bytes)
 */
std::vector<uint8_t> rsa_encrypt(
    const std::vector<uint8_t>& data,
    const RSAKeyPair* public_key
);

/**
 * @brief Decrypt data with RSA private key
 * @param data Encrypted data (256 bytes)
 * @param private_key Private key to decrypt with
 * @return Decrypted data
 */
std::vector<uint8_t> rsa_decrypt(
    const std::vector<uint8_t>& data,
    const RSAKeyPair* private_key
);

// ============================================================================
// AES-256-GCM ENCRYPTION
// ============================================================================

/**
 * @brief Encrypt data with AES-256-GCM
 * @param plaintext Data to encrypt
 * @param key 32-byte AES key
 * @return [nonce: 12 bytes][ciphertext][tag: 16 bytes]
 */
std::vector<uint8_t> aes_gcm_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key
);

/**
 * @brief Decrypt data with AES-256-GCM
 * @param ciphertext [nonce: 12 bytes][encrypted data][tag: 16 bytes]
 * @param key 32-byte AES key
 * @return Decrypted data (empty on failure)
 */
std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key
);

// ============================================================================
// XOR OBFUSCATION
// ============================================================================

/**
 * @brief XOR obfuscate string with key
 * @param data Data to obfuscate
 * @param key Obfuscation key
 * @return Base64-encoded obfuscated data
 */
std::string xor_obfuscate(const std::string& data, const std::string& key);

/**
 * @brief XOR deobfuscate string with key
 * @param obfuscated Base64-encoded obfuscated data
 * @param key Obfuscation key
 * @return Deobfuscated data
 */
std::string xor_deobfuscate(const std::string& obfuscated, const std::string& key);

// ============================================================================
// BASE64 ENCODING
// ============================================================================

/**
 * @brief Base64 encode (standard)
 */
std::string base64_encode(const std::vector<uint8_t>& data);

/**
 * @brief Base64 decode (standard)
 */
std::vector<uint8_t> base64_decode(const std::string& encoded);

/**
 * @brief Base64 URL-safe encode
 */
std::string base64url_encode(const std::vector<uint8_t>& data);

/**
 * @brief Base64 URL-safe decode
 */
std::vector<uint8_t> base64url_decode(const std::string& encoded);

// ============================================================================
// HASHING
// ============================================================================

/**
 * @brief SHA-256 hash
 * @param data Data to hash
 * @return 32-byte hash
 */
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

/**
 * @brief SHA-256 hash (string input)
 * @param data Data to hash
 * @return Hex-encoded hash string
 */
std::string sha256_hex(const std::string& data);

/**
 * @brief HMAC-SHA256
 * @param data Data to sign
 * @param key HMAC key
 * @return 32-byte MAC
 */
std::vector<uint8_t> hmac_sha256(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key
);

/**
 * @brief HMAC-SHA256 (string input/output)
 */
std::string hmac_sha256_hex(const std::string& data, const std::string& key);

// ============================================================================
// RANDOM
// ============================================================================

/**
 * @brief Generate cryptographically secure random bytes
 * @param length Number of bytes
 * @return Random bytes
 */
std::vector<uint8_t> random_bytes(size_t length);

// ============================================================================
// UTILITIES
// ============================================================================

/**
 * @brief Convert bytes to hex string
 */
std::string bytes_to_hex(const std::vector<uint8_t>& bytes);

/**
 * @brief Convert hex string to bytes
 */
std::vector<uint8_t> hex_to_bytes(const std::string& hex);

/**
 * @brief Constant-time comparison
 */
bool secure_compare(const std::string& a, const std::string& b);

} // namespace crypto
} // namespace oliviauth
