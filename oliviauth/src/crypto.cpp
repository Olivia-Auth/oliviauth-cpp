/**
 * @file crypto.cpp
 * @brief Cryptographic functions implementation using OpenSSL
 */

#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <stdexcept>
#include <cstring>
#include <algorithm>

namespace oliviauth {
namespace crypto {

// ============================================================================
// RSA KEY MANAGEMENT
// ============================================================================

struct RSAKeyPair {
    EVP_PKEY* pkey = nullptr;
    bool has_private = false;

    RSAKeyPair() = default;

    ~RSAKeyPair() {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }

    RSAKeyPair(const RSAKeyPair&) = delete;
    RSAKeyPair& operator=(const RSAKeyPair&) = delete;
};

RSAKeyPair* generate_keypair() {
    auto* keypair = new RSAKeyPair();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        delete keypair;
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        delete keypair;
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, internal::RSA_KEY_SIZE) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        delete keypair;
        return nullptr;
    }

    if (EVP_PKEY_keygen(ctx, &keypair->pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        delete keypair;
        return nullptr;
    }

    keypair->has_private = true;
    EVP_PKEY_CTX_free(ctx);
    return keypair;
}

void free_keypair(RSAKeyPair* keypair) {
    delete keypair;
}

std::string get_public_key_pem(const RSAKeyPair* keypair) {
    if (!keypair || !keypair->pkey) return "";

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    if (PEM_write_bio_PUBKEY(bio, keypair->pkey) != 1) {
        BIO_free(bio);
        return "";
    }

    BUF_MEM* buf;
    BIO_get_mem_ptr(bio, &buf);

    std::string pem(buf->data, buf->length);
    BIO_free(bio);
    return pem;
}

std::vector<uint8_t> get_public_key_bytes(const RSAKeyPair* keypair) {
    if (!keypair || !keypair->pkey) return {};

    // Get public key in DER format
    int len = i2d_PUBKEY(keypair->pkey, nullptr);
    if (len <= 0) return {};

    std::vector<uint8_t> der(len);
    uint8_t* ptr = der.data();
    i2d_PUBKEY(keypair->pkey, &ptr);

    return der;
}

RSAKeyPair* load_public_key_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return nullptr;

    auto* keypair = new RSAKeyPair();
    keypair->pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    keypair->has_private = false;

    BIO_free(bio);

    if (!keypair->pkey) {
        delete keypair;
        return nullptr;
    }

    return keypair;
}

RSAKeyPair* load_public_key_base64(const std::string& base64_key) {
    // Decode base64
    auto der = base64_decode(base64_key);
    if (der.empty()) return nullptr;

    auto* keypair = new RSAKeyPair();

    const uint8_t* ptr = der.data();
    keypair->pkey = d2i_PUBKEY(nullptr, &ptr, static_cast<long>(der.size()));
    keypair->has_private = false;

    if (!keypair->pkey) {
        delete keypair;
        return nullptr;
    }

    return keypair;
}

// ============================================================================
// RSA ENCRYPTION
// ============================================================================

std::vector<uint8_t> rsa_encrypt(
    const std::vector<uint8_t>& data,
    const RSAKeyPair* public_key
) {
    if (!public_key || !public_key->pkey) return {};

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key->pkey, nullptr);
    if (!ctx) return {};

    std::vector<uint8_t> result;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // Set OAEP padding with SHA-256
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // Determine output size
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    result.resize(outlen);

    // Encrypt
    if (EVP_PKEY_encrypt(ctx, result.data(), &outlen, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    result.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

std::vector<uint8_t> rsa_decrypt(
    const std::vector<uint8_t>& data,
    const RSAKeyPair* private_key
) {
    if (!private_key || !private_key->pkey || !private_key->has_private) return {};

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key->pkey, nullptr);
    if (!ctx) return {};

    std::vector<uint8_t> result;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // Set OAEP padding with SHA-256
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // Determine output size
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    result.resize(outlen);

    // Decrypt
    if (EVP_PKEY_decrypt(ctx, result.data(), &outlen, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    result.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

// ============================================================================
// AES-256-GCM ENCRYPTION
// ============================================================================

std::vector<uint8_t> aes_gcm_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key
) {
    if (key.size() != internal::AES_KEY_SIZE) return {};

    // Generate random nonce
    std::vector<uint8_t> nonce = random_bytes(internal::AES_NONCE_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> result;

    // Reserve space: nonce + ciphertext + tag
    result.reserve(internal::AES_NONCE_SIZE + plaintext.size() + internal::AES_TAG_SIZE);

    // Add nonce at the beginning
    result.insert(result.end(), nonce.begin(), nonce.end());

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, internal::AES_NONCE_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Encrypt
    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int outlen;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int ciphertext_len = outlen;

    // Finalize
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    ciphertext_len += outlen;
    ciphertext.resize(ciphertext_len);

    // Add ciphertext
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    // Get and add tag
    std::vector<uint8_t> tag(internal::AES_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, internal::AES_TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    result.insert(result.end(), tag.begin(), tag.end());

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key
) {
    if (key.size() != internal::AES_KEY_SIZE) return {};
    if (ciphertext.size() < internal::AES_NONCE_SIZE + internal::AES_TAG_SIZE) return {};

    // Extract nonce (first 12 bytes)
    std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + internal::AES_NONCE_SIZE);

    // Extract tag (last 16 bytes)
    std::vector<uint8_t> tag(ciphertext.end() - internal::AES_TAG_SIZE, ciphertext.end());

    // Extract encrypted data (middle)
    std::vector<uint8_t> encrypted(
        ciphertext.begin() + internal::AES_NONCE_SIZE,
        ciphertext.end() - internal::AES_TAG_SIZE
    );

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, internal::AES_NONCE_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Decrypt
    std::vector<uint8_t> plaintext(encrypted.size());
    int outlen;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, encrypted.data(), static_cast<int>(encrypted.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int plaintext_len = outlen;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, internal::AES_TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Finalize and verify tag
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return {};  // Authentication failed
    }

    plaintext_len += outlen;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// ============================================================================
// XOR OBFUSCATION
// ============================================================================

std::string xor_obfuscate(const std::string& data, const std::string& key) {
    if (key.empty()) return data;

    std::vector<uint8_t> result;
    result.reserve(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        result.push_back(static_cast<uint8_t>(data[i]) ^ static_cast<uint8_t>(key[i % key.size()]));
    }

    return base64url_encode(result);
}

std::string xor_deobfuscate(const std::string& obfuscated, const std::string& key) {
    if (key.empty()) return obfuscated;

    auto data = base64url_decode(obfuscated);
    if (data.empty()) return "";

    std::string result;
    result.reserve(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        result.push_back(static_cast<char>(data[i] ^ static_cast<uint8_t>(key[i % key.size()])));
    }

    return result;
}

// ============================================================================
// BASE64 ENCODING
// ============================================================================

std::string base64_encode(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);

    BUF_MEM* buf;
    BIO_get_mem_ptr(bio, &buf);

    std::string result(buf->data, buf->length);
    BIO_free_all(bio);

    return result;
}

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    if (encoded.empty()) return {};

    // Calculate approximate decoded length
    size_t len = encoded.size();
    size_t padding = 0;
    if (len >= 2) {
        if (encoded[len - 1] == '=') padding++;
        if (encoded[len - 2] == '=') padding++;
    }
    size_t decoded_len = (len * 3) / 4 - padding;

    std::vector<uint8_t> result(decoded_len + 1);

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int actual_len = BIO_read(bio, result.data(), static_cast<int>(result.size()));

    BIO_free_all(bio);

    if (actual_len <= 0) return {};

    result.resize(actual_len);
    return result;
}

std::string base64url_encode(const std::vector<uint8_t>& data) {
    std::string result = base64_encode(data);

    // Replace + with -, / with _
    for (char& c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }

    // Keep padding (=) for Python compatibility
    // Python's base64.urlsafe_b64decode requires padding

    return result;
}

std::vector<uint8_t> base64url_decode(const std::string& encoded) {
    std::string standard = encoded;

    // Replace - with +, _ with /
    for (char& c : standard) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }

    // Add padding if necessary
    switch (standard.size() % 4) {
        case 2: standard += "=="; break;
        case 3: standard += "="; break;
    }

    return base64_decode(standard);
}

// ============================================================================
// HASHING
// ============================================================================

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

std::string sha256_hex(const std::string& data) {
    std::vector<uint8_t> input(data.begin(), data.end());
    auto hash = sha256(input);
    return bytes_to_hex(hash);
}

std::vector<uint8_t> hmac_sha256(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key
) {
    std::vector<uint8_t> result(EVP_MAX_MD_SIZE);
    unsigned int len = 0;

    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         data.data(), data.size(),
         result.data(), &len);

    result.resize(len);
    return result;
}

std::string hmac_sha256_hex(const std::string& data, const std::string& key) {
    std::vector<uint8_t> data_vec(data.begin(), data.end());
    std::vector<uint8_t> key_vec(key.begin(), key.end());
    auto mac = hmac_sha256(data_vec, key_vec);
    return bytes_to_hex(mac);
}

// ============================================================================
// RANDOM
// ============================================================================

std::vector<uint8_t> random_bytes(size_t length) {
    std::vector<uint8_t> result(length);
    if (RAND_bytes(result.data(), static_cast<int>(length)) != 1) {
        // Fallback (not cryptographically secure, but better than nothing)
        for (size_t i = 0; i < length; ++i) {
            result[i] = static_cast<uint8_t>(rand() % 256);
        }
    }
    return result;
}

// ============================================================================
// UTILITIES
// ============================================================================

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);

    for (uint8_t byte : bytes) {
        result.push_back(hex_chars[(byte >> 4) & 0x0F]);
        result.push_back(hex_chars[byte & 0x0F]);
    }

    return result;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) return {};

    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = 0;
        for (int j = 0; j < 2; ++j) {
            byte <<= 4;
            char c = hex[i + j];
            if (c >= '0' && c <= '9') byte |= (c - '0');
            else if (c >= 'a' && c <= 'f') byte |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') byte |= (c - 'A' + 10);
            else return {};
        }
        result.push_back(byte);
    }

    return result;
}

bool secure_compare(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;

    volatile uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
    }

    return result == 0;
}

} // namespace crypto
} // namespace oliviauth
