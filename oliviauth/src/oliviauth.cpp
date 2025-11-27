/**
 * @file oliviauth.cpp
 * @brief Main OliviaAuth class implementation
 *
 * This is the core implementation matching the Python SDK behavior.
 */

#include "../include/oliviauth.h"
#include "crypto.h"
#include "hwid.h"
#include "http.h"
#include "xor.h"
#include "encrypted_value.h"
#include "anti_debug.h"
#include "integrity.h"
#include "transport/transport.h"
#include "transport/http_transport.h"
#include "transport/socketio_transport.h"

// JSON library
#ifdef OLIVIAUTH_USE_EXTERNAL_JSON
    #include <nlohmann/json.hpp>
#else
    #include "../deps/json.hpp"
#endif

#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstdlib>
#include <algorithm>

using json = nlohmann::json;

namespace oliviauth {

// ============================================================================
// SDK VERSION
// ============================================================================

static const char* SDK_VERSION = RXor("1.0.0");

const char* get_sdk_version() {
    return SDK_VERSION;
}

// ============================================================================
// DEBUG MODE
// ============================================================================

// Global debug mode (accessible from transport modules)
std::atomic<bool> g_debug_mode{false};
std::atomic<LogLevel> g_log_level{LogLevel::None};

void set_debug_mode(bool enabled) {
    g_debug_mode = enabled;
    if (enabled && g_log_level == LogLevel::None) {
        g_log_level = LogLevel::Debug;  // Enable all logs by default
    }
}

void set_log_level(LogLevel level) {
    g_log_level = level;
    if (level != LogLevel::None) {
        g_debug_mode = true;
    }
}

bool is_debug_mode() {
    return g_debug_mode;
}

LogLevel get_log_level() {
    return g_log_level;
}

// Internal logging helper
static void debug_log(LogLevel level, const std::string& category, const std::string& message) {
    if (!g_debug_mode || level > g_log_level) return;

    const char* level_str = "";
    const char* color_start = "";
    const char* color_end = RXor("\033[0m");

    switch (level) {
        case LogLevel::Error:
            level_str = RXor("ERROR");
            color_start = RXor("\033[31m");  // Red
            break;
        case LogLevel::Warning:
            level_str = RXor("WARN ");
            color_start = RXor("\033[33m");  // Yellow
            break;
        case LogLevel::Info:
            level_str = RXor("INFO ");
            color_start = RXor("\033[36m");  // Cyan
            break;
        case LogLevel::Debug:
            level_str = RXor("DEBUG");
            color_start = RXor("\033[90m");  // Gray
            break;
        default:
            return;
    }

    // Get current time
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &time);
#else
    localtime_r(&time, &tm_buf);
#endif

    std::cerr << color_start
              << "[" << std::setfill('0') << std::setw(2) << tm_buf.tm_hour
              << ":" << std::setw(2) << tm_buf.tm_min
              << ":" << std::setw(2) << tm_buf.tm_sec
              << "." << std::setw(3) << ms.count() << "] "
              << "[" << level_str << "] "
              << "[" << category << "] "
              << color_end
              << message << std::endl;
}

// Convenience macros for logging
#define LOG_ERROR(cat, msg) debug_log(LogLevel::Error, cat, msg)
#define LOG_WARN(cat, msg) debug_log(LogLevel::Warning, cat, msg)
#define LOG_INFO(cat, msg) debug_log(LogLevel::Info, cat, msg)
#define LOG_DEBUG(cat, msg) debug_log(LogLevel::Debug, cat, msg)

// ============================================================================
// GLOBAL UTILITY FUNCTIONS
// ============================================================================

std::string generate_hwid() {
    return hwid::generate();
}

bool validate_hwid(const std::string& id, size_t min_length) {
    return hwid::validate(id, min_length);
}

// ============================================================================
// OliviaAuth IMPLEMENTATION
// ============================================================================

class OliviaAuth::Impl {
public:
    // Configuration (Python-compatible order)
    std::string owner_id;
    std::string app_name;
    std::string version;
    std::string server_url;
    std::string client_key;
    std::string server_key;
    std::string hash_check;     // NEW: for loader integrity verification
    std::string ssl_sha256;     // SSL certificate fingerprint for pinning
    bool auto_init;
    int heartbeat_interval;
    Mode mode;
    bool auto_exit;

    // State (matches Python SDK)
    // SECURITY: Use encrypted flags to prevent memory patching attacks
    EncryptedBool initialized_{false};
    EncryptedBool authenticated_{false};
    EncryptedBool connected_{false};
    std::atomic<ConnectionState> connection_state_{ConnectionState::DISCONNECTED};
    std::string last_error_;
    std::string session_id_;
    std::string app_version_;
    UserData user_;

    // SECURITY: Redundant authentication tokens (interdependent)
    EncryptedInt64 auth_token_1_{0};
    EncryptedInt64 auth_token_2_{0};
    std::chrono::steady_clock::time_point auth_timestamp_;

    // Connection tracking (matches Python SDK)
    std::chrono::steady_clock::time_point last_connect_time_;
    std::atomic<int> reconnect_attempt_{0};
    static constexpr int MAX_RECONNECT_ATTEMPTS = 50;

    // Session heartbeat (pre-auth, matches Python SDK)
    std::atomic<bool> session_heartbeat_running_{false};
    std::thread session_heartbeat_thread_;
    std::condition_variable session_heartbeat_cv_;
    std::mutex session_heartbeat_mutex_;
    static constexpr int SESSION_HEARTBEAT_INTERVAL = 15;  // 15s pre-auth

    // Transport layer (HTTP or Socket.IO)
    std::unique_ptr<transport::Transport> transport_;

    // Crypto
    crypto::RSAKeyPair* keypair_ = nullptr;
    crypto::RSAKeyPair* server_pubkey_ = nullptr;

    // Threading
    std::atomic<bool> running_{false};
    std::thread heartbeat_thread_;
    std::thread watchdog_thread_;
    std::mutex mutex_;
    std::condition_variable stop_cv_;

    // Callbacks
    ConnectionCallback on_connect_;
    ConnectionCallback on_disconnect_;
    SessionExpiredCallback on_session_expired_;

    // Command handlers (for WebSocket mode)
    std::map<std::string, CommandHandler> command_handlers_;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() = default;

    ~Impl() {
        stop();

        if (keypair_) {
            crypto::free_keypair(keypair_);
        }
        if (server_pubkey_) {
            crypto::free_keypair(server_pubkey_);
        }
    }

    // ========================================================================
    // STOP / CLEANUP
    // ========================================================================

    void stop() {
        running_ = false;
        stop_session_heartbeat();
        stop_cv_.notify_all();

        if (heartbeat_thread_.joinable()) {
            heartbeat_thread_.join();
        }
        if (watchdog_thread_.joinable()) {
            watchdog_thread_.join();
        }
    }

    // ========================================================================
    // STATE MACHINE (matches Python SDK)
    // ========================================================================

    /**
     * @brief Transition to a new state with validation
     * @param new_state Target state
     * @return true if transition was valid, false otherwise
     */
    bool transition_state(ConnectionState new_state) {
        ConnectionState current = connection_state_.load();

        // Define valid transitions (matches Python _transition_state)
        bool valid = false;
        switch (current) {
            case ConnectionState::DISCONNECTED:
                valid = (new_state == ConnectionState::CONNECTING);
                break;
            case ConnectionState::CONNECTING:
                valid = (new_state == ConnectionState::CONNECTED ||
                         new_state == ConnectionState::DISCONNECTED);
                break;
            case ConnectionState::CONNECTED:
                valid = (new_state == ConnectionState::AUTHENTICATING ||
                         new_state == ConnectionState::DISCONNECTED);
                break;
            case ConnectionState::AUTHENTICATING:
                valid = (new_state == ConnectionState::AUTHENTICATED ||
                         new_state == ConnectionState::CONNECTED ||
                         new_state == ConnectionState::DISCONNECTED);
                break;
            case ConnectionState::AUTHENTICATED:
                valid = (new_state == ConnectionState::DISCONNECTED ||
                         new_state == ConnectionState::CONNECTING);  // For refresh
                break;
        }

        if (valid) {
            connection_state_ = new_state;
            LOG_DEBUG(RXor("STATE"), std::string(RXor("State transition: ")) + state_to_string(current) +
                      RXor(" -> ") + state_to_string(new_state));
        } else {
            LOG_WARN(RXor("STATE"), std::string(RXor("Invalid state transition: ")) + state_to_string(current) +
                     RXor(" -> ") + state_to_string(new_state));
        }

        return valid;
    }

    /**
     * @brief Force state without validation (for error recovery)
     * @param new_state Target state
     */
    void force_state(ConnectionState new_state) {
        ConnectionState old_state = connection_state_.exchange(new_state);
        LOG_DEBUG(RXor("STATE"), std::string(RXor("Force state: ")) + state_to_string(old_state) +
                  RXor(" -> ") + state_to_string(new_state));
    }

    /**
     * @brief Convert state to string for logging
     */
    static std::string state_to_string(ConnectionState state) {
        switch (state) {
            case ConnectionState::DISCONNECTED: return RXor("DISCONNECTED");
            case ConnectionState::CONNECTING: return RXor("CONNECTING");
            case ConnectionState::CONNECTED: return RXor("CONNECTED");
            case ConnectionState::AUTHENTICATING: return RXor("AUTHENTICATING");
            case ConnectionState::AUTHENTICATED: return RXor("AUTHENTICATED");
            default: return RXor("UNKNOWN");
        }
    }

    /**
     * @brief Check if connected (derived from state, matches Python)
     * Connected means: CONNECTED, AUTHENTICATING, or AUTHENTICATED
     */
    bool is_connected() const {
        ConnectionState state = connection_state_.load();
        return state == ConnectionState::CONNECTED ||
               state == ConnectionState::AUTHENTICATING ||
               state == ConnectionState::AUTHENTICATED;
    }

    /**
     * @brief Check if authenticated (derived from state, matches Python)
     */
    bool is_authenticated() const {
        return connection_state_.load() == ConnectionState::AUTHENTICATED;
    }

    // ========================================================================
    // SECURITY HELPERS
    // ========================================================================

    /**
     * @brief Generate varied error message to prevent pattern-based patching
     * @param check_number Which check failed (1, 2, 3, etc.)
     * @return Randomized error message
     */
    std::string get_varied_error_message(int check_number) {
        // Use timestamp + check number to vary message
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        int variant = (now + check_number) % 4;

        switch (variant) {
            case 0: return "Authentication failed #" + std::to_string(check_number);
            case 1: return "Verification error #" + std::to_string(check_number);
            case 2: return "Access denied #" + std::to_string(check_number);
            case 3: return "Security check failed #" + std::to_string(check_number);
            default: return "Authentication failed #" + std::to_string(check_number);
        }
    }

    /**
     * @brief Derive authentication tokens from session
     * Sets interdependent tokens that must all match for valid auth
     */
    void set_auth_tokens() {
        if (session_id_.empty()) {
            auth_token_1_ = 0;
            auth_token_2_ = 0;
            return;
        }

        // Derive token from session_id + username + timestamp
        std::string data = session_id_ + user_.username + user_.hwid;
        uint64_t hash = 0xcbf29ce484222325ULL; // FNV offset basis
        for (char c : data) {
            hash ^= static_cast<uint64_t>(c);
            hash *= 0x100000001b3ULL; // FNV prime
        }

        auth_token_1_ = static_cast<int64_t>(hash);
        auth_token_2_ = static_cast<int64_t>(hash ^ 0xCAFEBABEDEADBEEFULL);
        auth_timestamp_ = std::chrono::steady_clock::now();
    }

    /**
     * @brief Re-encrypt sensitive values with new keys (anti-dump)
     * Called periodically to make memory dumps less useful
     */
    void refresh_security_tokens() {
        // Re-encrypt boolean flags with new random keys
        bool auth_state = authenticated_.get();
        bool conn_state = connected_.get();
        bool init_state = initialized_.get();

        authenticated_ = auth_state;  // Triggers new key generation in EncryptedBool
        connected_ = conn_state;
        initialized_ = init_state;

        // Re-derive auth tokens with fresh keys
        if (auth_state && !session_id_.empty()) {
            set_auth_tokens();
        }
    }

    /**
     * @brief Quick authentication verification (CHECK #3)
     * Verifies multiple interdependent conditions
     * @return true if all auth checks pass
     */
    bool quick_auth_verify() const {
        // Check #3.1: Basic authenticated flag
        if (!authenticated_.get()) {
            return false;
        }

        // Check #3.2: Connection state matches
        if (connection_state_.load() != ConnectionState::AUTHENTICATED) {
            return false;
        }

        // Check #3.3: Session ID not empty
        if (session_id_.empty()) {
            return false;
        }

        // Check #3.4: Auth tokens are interdependent and valid
        int64_t token1 = auth_token_1_.get();
        int64_t token2 = auth_token_2_.get();
        if (token1 == 0 || token2 == 0) {
            return false;
        }

        // Check #3.5: Tokens must match expected relationship
        int64_t expected_token2 = token1 ^ 0xCAFEBABEDEADBEEFULL;
        if (token2 != expected_token2) {
            return false; // Tampering detected!
        }

        return true;
    }

    // ========================================================================
    // SESSION HEARTBEAT (pre-auth, matches Python SDK lines 1104-1131)
    // ========================================================================

    void start_session_heartbeat() {
        if (session_heartbeat_running_) {
            return;
        }

        LOG_DEBUG(RXor("SESSION-HB"), std::string(RXor("Starting session heartbeat (pre-auth, ")) +
                  std::to_string(SESSION_HEARTBEAT_INTERVAL) + RXor("s interval)"));
        session_heartbeat_running_ = true;

        // Send FIRST heartbeat IMMEDIATELY (matches Python line 1117-1118)
        if (mode == Mode::Socket && transport_ && !session_id_.empty()) {
            LOG_DEBUG(RXor("SESSION-HB"), RXor("Sending immediate first heartbeat"));
            json heartbeat_data = {{RXor("session_id"), session_id_}};
            transport_->emit(RXor("heartbeat"), heartbeat_data.dump());
        }

        session_heartbeat_thread_ = std::thread([this]() {
            while (session_heartbeat_running_ && !is_authenticated()) {
                std::unique_lock<std::mutex> lock(session_heartbeat_mutex_);

                // Wait for interval or stop signal
                if (session_heartbeat_cv_.wait_for(
                        lock,
                        std::chrono::seconds(SESSION_HEARTBEAT_INTERVAL),
                        [this]() { return !session_heartbeat_running_ || is_authenticated(); })) {
                    break;
                }

                if (!session_heartbeat_running_ || is_authenticated()) break;

                // Send session heartbeat to keep session alive during auth flow
                LOG_DEBUG(RXor("SESSION-HB"), RXor("Sending pre-auth heartbeat"));
                if (mode == Mode::Socket && transport_) {
                    json heartbeat_data = {{RXor("session_id"), session_id_}};
                    transport_->emit(RXor("heartbeat"), heartbeat_data.dump());
                }
            }
            LOG_DEBUG(RXor("SESSION-HB"), RXor("Session heartbeat stopped"));
        });
    }

    void stop_session_heartbeat() {
        if (!session_heartbeat_running_) {
            return;
        }

        session_heartbeat_running_ = false;
        session_heartbeat_cv_.notify_all();

        if (session_heartbeat_thread_.joinable()) {
            session_heartbeat_thread_.join();
        }
    }

    // ========================================================================
    // RECONNECTION WITH EXPONENTIAL BACKOFF (matches Python SDK)
    // ========================================================================

    void trigger_reconnect() {
        if (connection_state_ == ConnectionState::CONNECTING) {
            LOG_DEBUG(RXor("RECONNECT"), RXor("Already reconnecting, skipping"));
            return;
        }

        int attempt = reconnect_attempt_.fetch_add(1);
        if (attempt >= MAX_RECONNECT_ATTEMPTS) {
            LOG_ERROR(RXor("RECONNECT"), std::string(RXor("Max reconnect attempts (")) +
                      std::to_string(MAX_RECONNECT_ATTEMPTS) + RXor(") reached"));
            handle_permanent_disconnect();
            return;
        }

        // Calculate backoff with exponential delay (matches Python line 1283)
        // Base delay: 0.5s, max delay: 30s
        // Formula: 0.5 * 2^(attempt-1) = 0.5, 1, 2, 4, 8, 16, 30...
        double base_delay = 0.5;
        double max_delay = 30.0;
        int clamped_attempt = (attempt < 6) ? attempt : 6;
        double calc_delay = base_delay * (1 << clamped_attempt);
        double delay = (calc_delay < max_delay) ? calc_delay : max_delay;

        LOG_INFO(RXor("RECONNECT"), std::string(RXor("Reconnecting in ")) + std::to_string(delay) +
                 RXor("s (attempt ") + std::to_string(attempt + 1) + RXor("/") +
                 std::to_string(MAX_RECONNECT_ATTEMPTS) + RXor(")"));

        force_state(ConnectionState::CONNECTING);

        // Start reconnect in background thread
        std::thread([this, delay]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(delay * 1000)));

            if (!running_ || connection_state_ != ConnectionState::CONNECTING) {
                return;
            }

            try {
                if (transport_ && transport_->connect()) {
                    last_connect_time_ = std::chrono::steady_clock::now();
                    reconnect_attempt_ = 0;
                    transition_state(ConnectionState::CONNECTED);
                    LOG_INFO(RXor("RECONNECT"), RXor("Reconnected successfully"));

                    // Re-authenticate if we have a session
                    if (!session_id_.empty()) {
                        auto* socket_transport = dynamic_cast<transport::SocketIOTransport*>(transport_.get());
                        if (socket_transport) {
                            socket_transport->reauthenticate();
                            // Start refresh timer after successful reconnect (matches Python line 1298)
                            socket_transport->start_refresh_timer();
                        }
                    }
                } else {
                    LOG_WARN(RXor("RECONNECT"), RXor("Reconnect failed, will retry"));
                    force_state(ConnectionState::DISCONNECTED);
                    trigger_reconnect();  // Retry
                }
            } catch (const std::exception& e) {
                LOG_ERROR(RXor("RECONNECT"), std::string(RXor("Reconnect error: ")) + e.what());
                force_state(ConnectionState::DISCONNECTED);
                trigger_reconnect();  // Retry
            }
        }).detach();
    }

    void handle_permanent_disconnect() {
        // Called when all reconnection attempts exhausted (matches Python line 1364-1376)
        LOG_ERROR(RXor("RECONNECT"), RXor("Connection permanently lost after max attempts"));
        force_state(ConnectionState::DISCONNECTED);

        if (auto_exit) {
            std::cerr << RXor("\n[Olivia Auth] Failed to reconnect after multiple attempts. Closing...\n") << std::endl;

            if (on_session_expired_) {
                try {
                    on_session_expired_();
                } catch (...) {
                    // Ignore callback exceptions
                }
            }

            std::_Exit(1);
        }
    }

    void reset_reconnect_counter() {
        reconnect_attempt_ = 0;
    }

    // ========================================================================
    // EXCEPTION HELPER
    // ========================================================================

    [[noreturn]] void throw_error(const std::string& error) {
        // Log the error before throwing
        LOG_ERROR(RXor("AUTH"), error);

        // Map error messages to specific exceptions
        std::string lower_error = error;
        std::transform(lower_error.begin(), lower_error.end(), lower_error.begin(), ::tolower);

        if (lower_error.find(RXor("hwid")) != std::string::npos &&
            (lower_error.find(RXor("mismatch")) != std::string::npos || lower_error.find(RXor("wrong")) != std::string::npos)) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing HWIDMismatchError"));
            throw HWIDMismatchError(error);
        }
        if (lower_error.find(RXor("subscription")) != std::string::npos &&
            (lower_error.find(RXor("expired")) != std::string::npos || lower_error.find(RXor("paused")) != std::string::npos)) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing SubscriptionExpiredError"));
            throw SubscriptionExpiredError(error);
        }
        if (lower_error.find(RXor("banned")) != std::string::npos) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing UserBannedError"));
            throw UserBannedError(error);
        }
        if (lower_error.find(RXor("disabled")) != std::string::npos) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing AppDisabledError"));
            throw AppDisabledError(error);
        }
        if (lower_error.find(RXor("version")) != std::string::npos) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing VersionMismatchError"));
            throw VersionMismatchError(error);
        }
        if (lower_error.find(RXor("vpn")) != std::string::npos || lower_error.find(RXor("proxy")) != std::string::npos) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing VPNBlockedError"));
            throw VPNBlockedError(error);
        }
        if (lower_error.find(RXor("2fa")) != std::string::npos || lower_error.find(RXor("two-factor")) != std::string::npos ||
            lower_error.find(RXor("two factor")) != std::string::npos) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing TwoFactorRequiredError"));
            throw TwoFactorRequiredError(error);
        }
        if (lower_error.find(RXor("session")) != std::string::npos && lower_error.find(RXor("expired")) != std::string::npos) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing SessionExpiredError"));
            throw SessionExpiredError(error);
        }
        if (lower_error.find(RXor("not initialized")) != std::string::npos || lower_error.find(RXor("init")) != std::string::npos) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing NotInitializedError"));
            throw NotInitializedError(error);
        }
        if (lower_error.find(RXor("not authenticated")) != std::string::npos) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing NotAuthenticatedError"));
            throw NotAuthenticatedError(error);
        }
        if (lower_error.find(RXor("connect")) != std::string::npos || lower_error.find(RXor("network")) != std::string::npos ||
            lower_error.find(RXor("http")) != std::string::npos) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing ConnectionError"));
            throw ConnectionError(error);
        }
        if (lower_error.find(RXor("encrypt")) != std::string::npos || lower_error.find(RXor("decrypt")) != std::string::npos ||
            lower_error.find(RXor("crypto")) != std::string::npos) {
            LOG_DEBUG(RXor("AUTH"), RXor("Throwing EncryptionError"));
            throw EncryptionError(error);
        }

        // Default to AuthenticationError for unknown errors
        LOG_DEBUG(RXor("AUTH"), RXor("Throwing AuthenticationError (default)"));
        throw AuthenticationError(error);
    }

    // ========================================================================
    // ENCRYPTION HELPERS
    // ========================================================================

    std::string encrypt_request(const json& data, bool use_obfuscation = true) {
        if (!server_pubkey_) {
            return "";
        }

        // 1. Convert to JSON string
        std::string json_str = data.dump();
        std::vector<uint8_t> plaintext(json_str.begin(), json_str.end());

        // 2. Generate random AES key
        auto aes_key = crypto::random_bytes(crypto::AES_KEY_SIZE);

        // 3. Encrypt with AES-GCM
        auto aes_ciphertext = crypto::aes_gcm_encrypt(plaintext, aes_key);
        if (aes_ciphertext.empty()) {
            return "";
        }

        // 4. Encrypt AES key with RSA
        auto rsa_encrypted_key = crypto::rsa_encrypt(aes_key, server_pubkey_);
        if (rsa_encrypted_key.empty()) {
            return "";
        }

        // 5. Combine: RSA-encrypted-key + AES payload
        std::vector<uint8_t> combined;
        combined.reserve(rsa_encrypted_key.size() + aes_ciphertext.size());
        combined.insert(combined.end(), rsa_encrypted_key.begin(), rsa_encrypted_key.end());
        combined.insert(combined.end(), aes_ciphertext.begin(), aes_ciphertext.end());

        // 6. Base64 URL-safe encode
        std::string encoded = crypto::base64url_encode(combined);

        // 7. Optional XOR obfuscation with client key
        if (use_obfuscation && !client_key.empty()) {
            encoded = crypto::xor_obfuscate(encoded, client_key);
        }

        return encoded;
    }

    json decrypt_response(const std::string& encrypted_data, bool use_obfuscation = true) {
        if (!keypair_) {
            return json();
        }

        std::string data = encrypted_data;

        // 1. Optional XOR deobfuscation with server key
        if (use_obfuscation && !server_key.empty()) {
            data = crypto::xor_deobfuscate(data, server_key);
        }

        // 2. Base64 URL-safe decode
        auto combined = crypto::base64url_decode(data);
        if (combined.size() <= crypto::internal::RSA_CIPHERTEXT_SIZE) {
            return json();
        }

        // 3. Split into RSA-encrypted key and AES payload
        std::vector<uint8_t> rsa_encrypted_key(
            combined.begin(),
            combined.begin() + crypto::internal::RSA_CIPHERTEXT_SIZE
        );
        std::vector<uint8_t> aes_ciphertext(
            combined.begin() + crypto::internal::RSA_CIPHERTEXT_SIZE,
            combined.end()
        );

        // 4. Decrypt AES key with RSA
        auto aes_key = crypto::rsa_decrypt(rsa_encrypted_key, keypair_);
        if (aes_key.empty()) {
            return json();
        }

        // 5. Decrypt payload with AES-GCM
        auto plaintext = crypto::aes_gcm_decrypt(aes_ciphertext, aes_key);
        if (plaintext.empty()) {
            return json();
        }

        // 6. Parse JSON
        try {
            std::string json_str(plaintext.begin(), plaintext.end());
            auto result = json::parse(json_str);
            return result;
        } catch (...) {
            return json();
        }
    }

    // ========================================================================
    // HTTP HELPERS
    // ========================================================================

    json send_request(const std::string& endpoint, const json& data, bool obfuscate_request = true, bool obfuscate_response = true) {
        LOG_DEBUG(RXor("TRANSPORT"), std::string(RXor("Request to: ")) + endpoint);

        if (!transport_) {
            last_error_ = RXor("Transport not initialized");
            LOG_ERROR(RXor("TRANSPORT"), last_error_);
            return json{{RXor("success"), false}, {RXor("error"), last_error_}};
        }

        // Encrypt request data
        std::string encrypted = encrypt_request(data, obfuscate_request);
        if (encrypted.empty()) {
            last_error_ = RXor("Failed to encrypt request");
            LOG_ERROR(RXor("TRANSPORT"), last_error_);
            return json{{RXor("success"), false}, {RXor("error"), last_error_}};
        }

        // Add session header if we have one
        std::map<std::string, std::string> headers;
        if (!session_id_.empty()) {
            headers[RXor("Session-ID")] = session_id_;
        }

        // Build request body - different format for HTTP vs Socket.IO
        std::string body;
        if (mode == Mode::Socket) {
            // Socket.IO: server wraps data, so just send encrypted string
            body = encrypted;
        } else {
            // HTTP: need to wrap in {"data": encrypted}
            json request_body = {{RXor("data"), encrypted}};
            body = request_body.dump();
        }

        // Send request via transport layer
        auto response = transport_->send_request(endpoint, body, headers);

        // Check for HTTP 401 - session expired or deleted (matches Python line 1069-1073)
        if (response.status_code == 401) {
            std::cerr << RXor("[Olivia] Session expired or deleted (HTTP 401)") << std::endl;
            LOG_ERROR(RXor("TRANSPORT"), RXor("Session expired or deleted (HTTP 401)"));
            handle_session_killed();
            return json{{RXor("success"), false}, {RXor("error"), RXor("Session expired")}};
        }

        if (!response.ok()) {
            // Try to extract error message from response body (server sends JSON with "message" field)
            std::string error_msg = response.error;
            if (!response.body.empty()) {
                try {
                    auto error_json = json::parse(response.body);
                    if (error_json.contains(RXor("message")) && error_json[RXor("message")].is_string()) {
                        error_msg = error_json[RXor("message")].get<std::string>();
                    }
                } catch (...) {
                    // Body is not valid JSON, use default error
                }
            }
            last_error_ = error_msg;
            LOG_ERROR(RXor("TRANSPORT"), std::string(RXor("Request error: ")) + error_msg + RXor(" (status ") + std::to_string(response.status_code) + RXor(")"));
            LOG_DEBUG(RXor("TRANSPORT"), std::string(RXor("Response body: ")) + response.body);
            return json{{RXor("success"), false}, {RXor("error"), last_error_}};
        }

        LOG_DEBUG(RXor("TRANSPORT"), std::string(RXor("Response: status ")) + std::to_string(response.status_code));

        // Parse response JSON
        json response_json;
        try {
            response_json = json::parse(response.body);
        } catch (...) {
            last_error_ = RXor("Invalid JSON response");
            LOG_ERROR(RXor("TRANSPORT"), last_error_);
            LOG_DEBUG(RXor("TRANSPORT"), std::string(RXor("Raw response: ")) + response.body);
            return json{{RXor("success"), false}, {RXor("error"), last_error_}};
        }

        // Check for encrypted data field
        if (response_json.contains(RXor("data")) && response_json[RXor("data")].is_string()) {
            auto decrypted = decrypt_response(response_json[RXor("data")].get<std::string>(), obfuscate_response);
            if (!decrypted.is_null()) {
                LOG_DEBUG(RXor("TRANSPORT"), RXor("Response decrypted successfully"));
                return decrypted;
            }
            LOG_WARN(RXor("TRANSPORT"), RXor("Failed to decrypt response data"));
        }

        return response_json;
    }

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool do_init() {
        LOG_INFO(RXor("INIT"), RXor("Starting OliviaAuth initialization..."));

        // Update state
        force_state(ConnectionState::CONNECTING);

        // Generate RSA keypair
        LOG_DEBUG(RXor("INIT"), RXor("Generating RSA-2048 keypair..."));
        keypair_ = crypto::generate_keypair();
        if (!keypair_) {
            last_error_ = RXor("Failed to generate RSA keypair");
            LOG_ERROR(RXor("INIT"), last_error_);
            force_state(ConnectionState::DISCONNECTED);
            return false;
        }
        LOG_DEBUG(RXor("INIT"), RXor("RSA keypair generated"));

        // Create transport based on mode
        bool use_socket = (mode == Mode::Socket);
        std::string mode_str = use_socket ? RXor("Socket.IO") : RXor("HTTP");
        LOG_INFO(RXor("INIT"), std::string(RXor("Using ")) + mode_str + RXor(" transport for: ") + server_url);

        transport_ = transport::create_transport(server_url, use_socket);
        transport_->set_timeout(30);

        // Connect transport
        if (!transport_->connect()) {
            last_error_ = std::string(RXor("Failed to connect transport: ")) + transport_->get_last_error();
            LOG_ERROR(RXor("INIT"), last_error_);
            force_state(ConnectionState::DISCONNECTED);
            return false;
        }
        LOG_DEBUG(RXor("INIT"), RXor("Transport connected"));

        // Track connection time (matches Python)
        last_connect_time_ = std::chrono::steady_clock::now();
        transition_state(ConnectionState::CONNECTED);

        // Configure and verify SSL certificate fingerprint if provided
        if (!ssl_sha256.empty()) {
            LOG_DEBUG(RXor("INIT"), RXor("Configuring SSL certificate pinning..."));

            if (use_socket) {
                // Socket.IO mode: verify SSL before WebSocket connection
                auto* socket_transport = dynamic_cast<transport::SocketIOTransport*>(transport_.get());
                if (socket_transport) {
                    socket_transport->set_ssl_fingerprint(ssl_sha256);
                    try {
                        socket_transport->verify_ssl_fingerprint(ssl_sha256);
                        LOG_INFO(RXor("INIT"), RXor("SSL certificate fingerprint verified (Socket.IO)"));
                    } catch (const std::exception& e) {
                        last_error_ = std::string(RXor("SSL verification failed: ")) + std::string(e.what());
                        LOG_ERROR(RXor("INIT"), last_error_);
                        return false;
                    }
                }
            } else {
                // HTTP mode: verify SSL on every request
                auto* http_transport = dynamic_cast<transport::HTTPTransport*>(transport_.get());
                if (http_transport) {
                    http_transport->set_ssl_fingerprint(ssl_sha256);
                    try {
                        http_transport->verify_ssl_fingerprint(ssl_sha256);
                        LOG_INFO(RXor("INIT"), RXor("SSL certificate fingerprint verified (will check on every request)"));
                    } catch (const std::exception& e) {
                        last_error_ = std::string(RXor("SSL verification failed: ")) + std::string(e.what());
                        LOG_ERROR(RXor("INIT"), last_error_);
                        return false;
                    }
                }
            }
        }

        // Setup event handlers for Socket.IO mode
        if (use_socket) {
            setup_socket_event_handlers();
        }

        // Create session
        if (!create_session()) {
            LOG_ERROR(RXor("INIT"), RXor("Failed to create session"));
            return false;
        }

        // Authenticate Socket.IO connection with session_id BEFORE calling any API endpoints
        if (use_socket) {
            auto* socket_transport = dynamic_cast<transport::SocketIOTransport*>(transport_.get());
            if (socket_transport) {
                socket_transport->reauthenticate();
                // Wait a bit for server to process authentication
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }

        // Initialize app
        bool init_result = init_app();
        if (!init_result) {
            LOG_ERROR(RXor("INIT"), RXor("Failed to initialize app"));
            return false;
        }

        initialized_ = true;
        connected_ = true;
        LOG_INFO(RXor("INIT"), RXor("OliviaAuth initialized successfully!"));
        return true;
    }

    void handle_session_killed() {
        // Matches Python's _handle_session_killed() behavior (lines 1247-1259)
        LOG_ERROR(RXor("SESSION"), RXor("Session killed by server"));

        // Update all state flags
        authenticated_ = false;
        initialized_ = false;
        connected_ = false;
        force_state(ConnectionState::DISCONNECTED);

        // Stop all background processes
        stop_session_heartbeat();
        running_ = false;
        stop_cv_.notify_all();

        if (auto_exit) {
            std::cerr << "\n[Olivia Auth] Session expired or was terminated. Closing application...\n" << std::endl;

            if (on_session_expired_) {
                try {
                    on_session_expired_();
                } catch (...) {
                    // Ignore callback exceptions
                }
            }

            // Force exit (cannot be caught) - matches Python's os._exit(1)
            std::_Exit(1);
        }
    }

    void setup_socket_event_handlers() {
        LOG_DEBUG(RXor("INIT"), RXor("Setting up Socket.IO event handlers"));

        // Handle session expiration - matches Python lines 766-775
        transport_->on_event(RXor("session_expired"), [this](const std::string& data) {
            LOG_WARN(RXor("SESSION"), RXor("Server sent session_expired event"));

            std::string reason = RXor("unknown");
            try {
                if (!data.empty()) {
                    auto parsed = json::parse(data);
                    if (parsed.contains(RXor("reason"))) {
                        reason = parsed[RXor("reason")].get<std::string>();
                    } else if (parsed.contains(RXor("message"))) {
                        reason = parsed[RXor("message")].get<std::string>();
                    }
                }
            } catch (...) {}

            std::cerr << RXor("[Olivia] Session terminated by server: ") << reason << std::endl;
            LOG_WARN(RXor("SESSION"), std::string(RXor("Session terminated: ")) + reason);

            handle_session_killed();
        });

        // Handle auth_response - from 'authenticate' event
        transport_->on_event(RXor("auth_response"), [this](const std::string& data) {
            try {
                auto parsed = json::parse(data);
                bool success = parsed.value(RXor("success"), false);
                std::string message = parsed.value(RXor("message"), "");

                if (success) {
                    std::string room_id = parsed.value(RXor("room_id"), "");
                    std::string room_preview = room_id.length() > 16 ? room_id.substr(0, 16) + "..." : room_id;
                    LOG_INFO(RXor("AUTH"), std::string(RXor("Authenticated and joined room: ")) + room_preview);
                } else {
                }
            } catch (const std::exception& e) {
                LOG_ERROR(RXor("AUTH"), std::string(RXor("Failed to parse auth_response: ")) + e.what());
            } catch (...) {
                LOG_ERROR(RXor("AUTH"), RXor("Failed to parse auth_response: unknown error"));
            }
        });

        // Handle heartbeat ACK - matches Python lines 722-750
        transport_->on_event(RXor("heartbeat_ack"), [this](const std::string& data) {
            try {
                auto parsed = json::parse(data);
                bool session_dead = false;
                std::string reason = "";

                // NOTE: We ignore "authenticated=false" because it can happen during reconnection
                // when the server doesn't yet have conn_info for the new socket connection.
                // This is a transient state that resolves once re-authentication completes.

                // Check session_alive field (reliable - server actually checked the session)
                if (parsed.contains(RXor("session_alive")) && parsed[RXor("session_alive")].is_boolean() && !parsed[RXor("session_alive")].get<bool>()) {
                    session_dead = true;
                    reason = RXor("session_alive=false");
                }
                // Also decrypt and check success field for killed sessions
                // IMPORTANT: Only check success=false if already authenticated, otherwise
                // failed auth attempts will be interpreted as "session killed"
                else if (authenticated_ && parsed.contains(RXor("data")) && parsed[RXor("data")].is_string()) {
                    try {
                        auto decrypted = decrypt_response(parsed[RXor("data")].get<std::string>(), true);
                        if (!decrypted.is_null() && decrypted.contains(RXor("success")) && !decrypted[RXor("success")].get<bool>()) {
                            session_dead = true;
                            std::string msg = decrypted.value(RXor("message"), RXor("no message"));
                            reason = std::string(RXor("decrypted.success=false: ")) + msg;
                        }
                    } catch (...) {}
                }

                if (session_dead) {
                    std::cerr << RXor("[Olivia] Server killed session: ") << reason << std::endl;
                    LOG_WARN(RXor("SESSION"), std::string(RXor("Server killed session: ")) + reason);
                    handle_session_killed();
                }
            } catch (...) {
                // Ignore malformed heartbeat_ack
            }
        });

        // Handle server commands
        transport_->on_event(RXor("server_command"), [this](const std::string& data) {
            handle_server_command(data);
        });

        // Handle disconnect
        transport_->on_event(RXor("disconnect"), [this](const std::string& /*data*/) {
            LOG_WARN(RXor("TRANSPORT"), RXor("Disconnected from server"));
            connected_ = false;

            ConnectionState prev_state = connection_state_.load();
            force_state(ConnectionState::DISCONNECTED);

            if (on_disconnect_) {
                on_disconnect_();
            }

            // Trigger reconnect if we were authenticated (matches Python behavior)
            if (prev_state == ConnectionState::AUTHENTICATED && running_ && !auto_exit) {
                LOG_INFO(RXor("TRANSPORT"), RXor("Was authenticated, triggering reconnect..."));
                trigger_reconnect();
            }
        });

        // Handle reconnect
        transport_->on_event(RXor("connect"), [this](const std::string& /*data*/) {
            LOG_INFO(RXor("TRANSPORT"), RXor("Reconnected to server"));
            connected_ = true;
            last_connect_time_ = std::chrono::steady_clock::now();
            transition_state(ConnectionState::CONNECTED);

            if (on_connect_) {
                on_connect_();
            }
        });
    }

    void handle_server_command(const std::string& encrypted_data) {
        LOG_DEBUG(RXor("COMMAND"), RXor("Received server command"));

        // Decrypt command data
        auto decrypted = decrypt_response(encrypted_data, true);
        if (decrypted.is_null()) {
            LOG_ERROR(RXor("COMMAND"), RXor("Failed to decrypt command"));
            return;
        }

        std::string command_id = decrypted.value(RXor("command_id"), "");
        std::string command_name = decrypted.value(RXor("command"), "");
        json params = decrypted.value(RXor("params"), json::object());

        LOG_INFO(RXor("COMMAND"), std::string(RXor("Command: ")) + command_name + RXor(" (id: ") + command_id + RXor(")"));

        // Send ACK for received
        send_command_ack(command_id, RXor("received"));

        // Execute handler if registered
        if (command_handlers_.count(command_name)) {
            try {
                std::string result = command_handlers_[command_name](params.dump());
                send_command_ack(command_id, RXor("executed"), result);
                LOG_DEBUG(RXor("COMMAND"), RXor("Command executed successfully"));
            } catch (const std::exception& e) {
                send_command_ack(command_id, RXor("failed"), e.what());
                LOG_ERROR(RXor("COMMAND"), std::string(RXor("Command failed: ")) + e.what());
            }
        } else {
            send_command_ack(command_id, RXor("failed"), RXor("Unknown command"));
            LOG_WARN(RXor("COMMAND"), std::string(RXor("Unknown command: ")) + command_name);
        }
    }

    void send_command_ack(const std::string& command_id, const std::string& status,
                          const std::string& response = "") {
        json ack = {
            {RXor("command_id"), command_id},
            {RXor("status"), status}
        };
        if (!response.empty()) {
            ack[RXor("response")] = response;
        }
        transport_->emit(RXor("command_ack"), ack.dump());
    }

    bool create_session() {
        LOG_INFO(RXor("SESSION"), RXor("Creating new session..."));
        LOG_DEBUG(RXor("SESSION"), std::string(RXor("Server URL: ")) + server_url);

        // Get public key as PEM string, then base64 URL-safe encode it
        // Server expects: base64url(PEM bytes)
        std::string pubkey_pem = crypto::get_public_key_pem(keypair_);
        std::vector<uint8_t> client_pem_bytes(pubkey_pem.begin(), pubkey_pem.end());
        std::string pubkey_b64 = crypto::base64url_encode(client_pem_bytes);
        LOG_DEBUG(RXor("SESSION"), RXor("Generated client public key (PEM, base64url encoded)"));

        json response_json;

        if (mode == Mode::Socket) {
            // Socket.IO mode: use create_session event
            LOG_DEBUG(RXor("SESSION"), RXor("Using Socket.IO create_session event"));

            // Register handler for session_created response
            std::mutex session_mutex;
            std::condition_variable session_cv;
            bool session_received = false;
            json session_response;

            transport_->on_event(RXor("session_created"), [&](const std::string& data) {
                LOG_DEBUG(RXor("SESSION"), RXor("Received session_created event"));
                try {
                    session_response = json::parse(data);
                    session_received = true;
                    session_cv.notify_all();
                } catch (...) {}
            });

            transport_->on_event(RXor("session_error"), [&](const std::string& data) {
                LOG_ERROR(RXor("SESSION"), RXor("Received session_error event"));
                try {
                    session_response = json::parse(data);
                    session_received = true;
                    session_cv.notify_all();
                } catch (...) {}
            });

            // Emit create_session event
            json create_data = {{RXor("public_key"), pubkey_b64}};
            transport_->emit(RXor("create_session"), create_data.dump());

            // Wait for response
            {
                std::unique_lock<std::mutex> lock(session_mutex);
                if (!session_cv.wait_for(lock, std::chrono::seconds(30), [&]{ return session_received; })) {
                    last_error_ = RXor("Session creation timeout");
                    LOG_ERROR(RXor("SESSION"), last_error_);
                    return false;
                }
            }

            if (!session_response.value(RXor("success"), false)) {
                last_error_ = session_response.value(RXor("message"), RXor("Session creation failed"));
                LOG_ERROR(RXor("SESSION"), last_error_);
                return false;
            }

            // Extract session ID and server public key
            session_id_ = session_response.value(RXor("session_id"), "");
            std::string server_pubkey_b64 = session_response.value(RXor("server_public_key"), "");


            if (session_id_.empty()) {
                last_error_ = RXor("No session ID received");
                LOG_ERROR(RXor("SESSION"), last_error_);
                return false;
            }

            // IMPORTANT: Set session_id in transport so it's sent with future requests
            transport_->set_session_id(session_id_);

            response_json[RXor("data")] = server_pubkey_b64;

        } else {
            // HTTP mode: use transport request
            json request_body = {{RXor("data"), pubkey_b64}};

            LOG_DEBUG(RXor("SESSION"), RXor("Request to: session"));
            auto response = transport_->send_request(RXor("session"), request_body.dump());

            if (!response.ok()) {
                last_error_ = std::string(RXor("Session creation failed: ")) + response.error;
                LOG_ERROR(RXor("SESSION"), last_error_ + RXor(" (status ") + std::to_string(response.status_code) + RXor(")"));
                LOG_DEBUG(RXor("SESSION"), std::string(RXor("Response body: ")) + response.body);
                return false;
            }

            // Parse response
            try {
                response_json = json::parse(response.body);
            } catch (...) {
                last_error_ = RXor("Invalid session response");
                LOG_ERROR(RXor("SESSION"), last_error_);
                LOG_DEBUG(RXor("SESSION"), std::string(RXor("Raw response: ")) + response.body);
                return false;
            }

            // Check for error response
            if (response_json.contains("error")) {
                last_error_ = response_json.value("error", "Session creation failed");
                LOG_ERROR("SESSION", last_error_);
                return false;
            }

            // Extract session ID from 'extra' field
            session_id_ = response_json.value("extra", "");
            if (session_id_.empty()) {
                session_id_ = response_json.value("session_id", "");
            }

            if (session_id_.empty()) {
                last_error_ = "No session ID received";
                LOG_ERROR("SESSION", last_error_);
                return false;
            }
        }

        LOG_DEBUG("SESSION", "Session ID: " + session_id_.substr(0, 16) + "...");

        // Set session ID in transport for future requests
        transport_->set_session_id(session_id_);

        // For Socket.IO mode: re-authenticate to join room for real-time events
        if (mode == Mode::Socket) {
            auto* socket_transport = dynamic_cast<transport::SocketIOTransport*>(transport_.get());
            if (socket_transport) {
                LOG_DEBUG("SESSION", "Re-authenticating Socket.IO with session_id to join room");
                try {
                    socket_transport->reauthenticate();
                    LOG_DEBUG("SESSION", "Reauthenticate call completed");
                } catch (const std::exception& e) {
                    LOG_ERROR("SESSION", std::string("Reauthenticate failed: ") + e.what());
                } catch (...) {
                    LOG_ERROR("SESSION", "Reauthenticate failed: unknown error");
                }
            }
        }

        LOG_DEBUG("SESSION", "Continuing after reauthenticate...");

        // Load server public key (base64url-encoded PEM)
        std::string server_pubkey_b64 = response_json.value("data", "");
        if (server_pubkey_b64.empty()) {
            last_error_ = "No server public key received";
            LOG_ERROR("SESSION", last_error_);
            return false;
        }

        // Decode base64url to get PEM bytes, then convert to string
        auto server_pem_bytes = crypto::base64url_decode(server_pubkey_b64);
        if (server_pem_bytes.empty()) {
            last_error_ = "Failed to decode server public key";
            LOG_ERROR("SESSION", last_error_);
            return false;
        }
        std::string server_pubkey_pem(server_pem_bytes.begin(), server_pem_bytes.end());
        LOG_DEBUG("SESSION", "Server public key PEM received");

        server_pubkey_ = crypto::load_public_key_pem(server_pubkey_pem);
        if (!server_pubkey_) {
            last_error_ = "Failed to load server public key";
            LOG_ERROR("SESSION", last_error_);
            LOG_DEBUG("SESSION", "PEM data: " + server_pubkey_pem.substr(0, 50) + "...");
            return false;
        }

        LOG_INFO("SESSION", "Session created successfully");

        // Start session heartbeat to keep session alive during auth flow (matches Python)
        if (mode == Mode::Socket) {
            start_session_heartbeat();
        }

        return true;
    }

    bool init_app() {
        LOG_INFO(RXor("INIT"), std::string(RXor("Initializing app: ")) + app_name + RXor(" v") + version);
        LOG_DEBUG(RXor("INIT"), std::string(RXor("Owner ID: ")) + owner_id);

        json init_data = {
            {RXor("ownerID"), owner_id},
            {RXor("appName"), app_name},
            {RXor("version"), version}
        };

        // Add hash check if provided (for loader integrity verification)
        if (!hash_check.empty()) {
            init_data[RXor("hashCheck")] = hash_check;
            LOG_DEBUG(RXor("INIT"), RXor("Hash check provided"));
        }

        // Init request: NO obfuscation on request, WITH obfuscation on response
        LOG_DEBUG(RXor("INIT"), RXor("Sending init request..."));
        auto response = send_request(RXor("init"), init_data, false, true);

        bool success = response.value(RXor("success"), false);

        if (!success) {
            last_error_ = response.value(RXor("error"), RXor("App initialization failed"));

            // Also try to get "message" field
            if (response.contains(RXor("message"))) {
                std::string msg = response.value(RXor("message"), "");
                last_error_ = msg;
            }

            LOG_ERROR(RXor("INIT"), last_error_);
            return false;
        }

        // Store app version if provided
        if (response.contains(RXor("info")) && response[RXor("info")].is_object()) {
            app_version_ = response[RXor("info")].value(RXor("version"), "");
            LOG_DEBUG(RXor("INIT"), std::string(RXor("Server app version: ")) + app_version_);
        }

        LOG_INFO(RXor("INIT"), RXor("App initialized successfully"));
        return true;
    }

    // ========================================================================
    // AUTHENTICATION
    // ========================================================================

    bool do_license(const std::string& license_key, const std::string& user_hwid) {
        LOG_INFO("LICENSE", "Authenticating with license key...");

        #ifdef _WIN32
        // SECURITY: Anti-debug check - silently fail if debugger detected
        if (antidebug::is_being_debugged()) {
            last_error_ = get_varied_error_message(1);
            LOG_ERROR("SECURITY", "Anti-debug check failed");
            return false;
        }

        // SECURITY: Code integrity check - detect binary patches + cross-verify
        bool patch_check = integrity::verify_no_obvious_patches();
        bool func_check = integrity::verify_integrity_function();

        if (!patch_check || !func_check) {
            last_error_ = get_varied_error_message(2);
            return false;
        }
        #endif

        transition_state(ConnectionState::AUTHENTICATING);

        std::string hwid = user_hwid.empty() ? generate_hwid() : user_hwid;
        LOG_DEBUG("LICENSE", "HWID: " + hwid.substr(0, 16) + "...");

        json auth_data = {
            {RXor("license"), license_key},
            {RXor("hwid"), hwid}
        };

        auto response = send_request(RXor("license"), auth_data);

        if (!response.value(RXor("success"), false)) {
            last_error_ = response.value(RXor("error"), RXor("License authentication failed"));
            LOG_ERROR("LICENSE", last_error_);
            transition_state(ConnectionState::CONNECTED);  // Back to connected but not auth
            return false;
        }

        // Parse user data
        if (response.contains(RXor("data")) && response[RXor("data")].is_object()) {
            LOG_INFO("LICENSE", ">>> Creating UserData from response");
            UserData temp_user(response[RXor("data")].dump());
            LOG_INFO("LICENSE", ">>> UserData created, now assigning to user_");
            user_ = std::move(temp_user);
            LOG_INFO("LICENSE", ">>> Assignment complete");
            LOG_INFO("LICENSE", "Authenticated as: " + user_.username);
        }

        // Stop pre-auth heartbeat and transition to authenticated (matches Python)
        stop_session_heartbeat();
        authenticated_ = true;
        transition_state(ConnectionState::AUTHENTICATED);
        reset_reconnect_counter();

        // SECURITY: Set interdependent authentication tokens
        set_auth_tokens();

        // Start background threads
        LOG_DEBUG("LICENSE", "Starting heartbeat and watchdog threads");
        LOG_INFO("LICENSE", ">>> About to start_heartbeat()");
        start_heartbeat();
        LOG_INFO("LICENSE", ">>> Heartbeat started, about to start_watchdog()");
        start_watchdog();
        LOG_INFO("LICENSE", ">>> Watchdog started, returning true");

        return true;
    }

    bool do_login(const std::string& username, const std::string& password,
                  const std::string& user_hwid, const std::string& two_factor) {
        LOG_INFO("LOGIN", "Authenticating user: " + username);

        #ifdef _WIN32
        // SECURITY: Anti-debug check - silently fail if debugger detected
        if (antidebug::is_being_debugged()) {
            last_error_ = get_varied_error_message(1);
            return false;
        }

        // SECURITY: Code integrity check - detect binary patches + cross-verify
        if (!integrity::cross_verify_all()) {
            last_error_ = get_varied_error_message(2);
            return false;
        }
        #endif

        transition_state(ConnectionState::AUTHENTICATING);

        std::string hwid = user_hwid.empty() ? generate_hwid() : user_hwid;
        LOG_DEBUG("LOGIN", "HWID: " + hwid.substr(0, 16) + "...");

        json auth_data = {
            {RXor("username"), username},
            {RXor("password"), password},
            {RXor("hwid"), hwid}
        };

        if (!two_factor.empty()) {
            auth_data[RXor("twoFactorCode")] = two_factor;
            LOG_DEBUG(RXor("LOGIN"), RXor("2FA code provided"));
        }

        auto response = send_request(RXor("login"), auth_data);

        if (!response.value(RXor("success"), false)) {
            last_error_ = response.value(RXor("error"), RXor("Login failed"));
            LOG_ERROR("LOGIN", last_error_);
            transition_state(ConnectionState::CONNECTED);  // Back to connected but not auth
            return false;
        }

        // Parse user data
        if (response.contains(RXor("data")) && response[RXor("data")].is_object()) {
            user_ = UserData(response[RXor("data")].dump());
            LOG_INFO("LOGIN", "Authenticated as: " + user_.username);
        }

        // Stop pre-auth heartbeat and transition to authenticated (matches Python)
        stop_session_heartbeat();
        authenticated_ = true;
        transition_state(ConnectionState::AUTHENTICATED);
        reset_reconnect_counter();

        // SECURITY: Set interdependent authentication tokens
        set_auth_tokens();

        // Start background threads
        LOG_DEBUG("LOGIN", "Starting heartbeat and watchdog threads");
        start_heartbeat();
        start_watchdog();

        return true;
    }

    bool do_register(const std::string& license_key, const std::string& username,
                     const std::string& password, const std::string& user_hwid) {
        LOG_INFO("REGISTER", "Registering new user: " + username);

        #ifdef _WIN32
        // SECURITY: Anti-debug check - silently fail if debugger detected
        if (antidebug::is_being_debugged()) {
            last_error_ = std::string(RXor("Registration ")) + get_varied_error_message(1);
            return false;
        }

        // SECURITY: Code integrity check - detect binary patches + cross-verify
        if (!integrity::cross_verify_all()) {
            last_error_ = std::string(RXor("Registration ")) + get_varied_error_message(2);
            return false;
        }
        #endif

        std::string hwid = user_hwid.empty() ? generate_hwid() : user_hwid;
        LOG_DEBUG("REGISTER", "HWID: " + hwid.substr(0, 16) + "...");

        json reg_data = {
            {RXor("license"), license_key},
            {RXor("username"), username},
            {RXor("password"), password},
            {RXor("hwid"), hwid}
        };

        auto response = send_request(RXor("register"), reg_data);

        if (!response.value(RXor("success"), false)) {
            last_error_ = response.value(RXor("error"), RXor("Registration failed"));
            LOG_ERROR("REGISTER", last_error_);
            return false;
        }

        LOG_INFO("REGISTER", "User registered successfully");
        return true;
    }

    // ========================================================================
    // HEARTBEAT
    // ========================================================================

    void start_heartbeat() {
        LOG_INFO("HEARTBEAT", ">>> start_heartbeat() called");
        running_ = true;

        int interval = heartbeat_interval;
        if (interval == 0) {
            interval = (mode == Mode::Socket) ? 30 : 60;
        }

        LOG_INFO("HEARTBEAT", ">>> Creating heartbeat thread with interval " + std::to_string(interval));
        heartbeat_thread_ = std::thread([this, interval]() {
            LOG_INFO("HEARTBEAT", ">>> Heartbeat thread started");

            while (running_) {
                std::unique_lock<std::mutex> lock(mutex_);

                // Wait for interval or stop signal
                if (stop_cv_.wait_for(lock, std::chrono::seconds(interval),
                    [this]{ return !running_.load(); })) {
                    break;
                }

                if (!running_ || !authenticated_) break;

                // Send heartbeat
                do_heartbeat();

                // SECURITY: Re-encrypt sensitive values periodically (anti-dump)
                refresh_security_tokens();
            }
        });
    }

    bool do_heartbeat() {
        // Require session_id (matches Python line 1051-1052)
        if (session_id_.empty()) {
            return false;
        }

        #ifdef _WIN32
        // SECURITY CHECK #1: Anti-debug in heartbeat - SILENT corruption
        if (antidebug::is_being_debugged()) {
            // Don't return false - too obvious
            // Silently corrupt session so server rejects it
            session_id_.clear();
            authenticated_ = false;
            auth_token_1_ = 0;
            auth_token_2_ = 0;
            return true; // Pretend success to avoid detection
        }

        // SECURITY CHECK #2: Code integrity in heartbeat - SILENT corruption
        if (!integrity::verify_no_obvious_patches()) {
            session_id_.clear();
            authenticated_ = false;
            auth_token_1_ = 0;
            auth_token_2_ = 0;
            return true;
        }

        // SECURITY CHECK #3: Verify auth tokens haven't been tampered
        if (authenticated_.get()) {
            int64_t token1 = auth_token_1_.get();
            int64_t token2 = auth_token_2_.get();
            if (token1 != 0 && token2 != 0) {
                int64_t expected = token1 ^ 0xCAFEBABEDEADBEEFULL;
                if (token2 != expected) {
                    // Token tampering detected!
                    session_id_.clear();
                    authenticated_ = false;
                    auth_token_1_ = 0;
                    auth_token_2_ = 0;
                    return true;
                }
            }
        }
        #endif

        if (mode == Mode::Socket) {
            // Check state before sending (matches Python lines 1057-1069)
            // Only send if AUTHENTICATED or CONNECTED (initial pre-auth heartbeat)
            // Skip during reconnection (CONNECTING, AUTHENTICATING, DISCONNECTED)
            ConnectionState state = connection_state_.load();
            if (state != ConnectionState::AUTHENTICATED && state != ConnectionState::CONNECTED) {
                LOG_DEBUG("HEARTBEAT", "Skipping heartbeat - state is " + state_to_string(state));
                return false;
            }

            // Socket.IO: Use lightweight event without full encryption
            LOG_DEBUG(RXor("HEARTBEAT"), RXor("Sending Socket.IO heartbeat"));
            json heartbeat_data = {{RXor("session_id"), session_id_}};
            transport_->emit(RXor("heartbeat"), heartbeat_data.dump());
            return true;
        } else {
            // HTTP: Use full encrypted request
            LOG_DEBUG(RXor("HEARTBEAT"), RXor("Sending HTTP heartbeat"));
            json heartbeat_data = {};
            auto response = send_request(RXor("heartbeat"), heartbeat_data);

            if (!response.value(RXor("success"), false)) {
                // Session was killed/deleted on server (matches Python behavior)
                std::string error_msg = response.value(RXor("error"), response.value(RXor("message"), RXor("session invalid")));
                LOG_WARN("HEARTBEAT", "Heartbeat failed: " + error_msg);
                std::cerr << "[Olivia] Heartbeat failed: " << error_msg << std::endl;
                handle_session_killed();
                return false;
            }

            return true;
        }
    }

    // ========================================================================
    // WATCHDOG (Auto-Exit)
    // ========================================================================

    void start_watchdog() {
        // Simplified watchdog - matches Python's simplified design (lines 1279-1316)
        // Most termination logic is now in handle_session_killed()
        // Watchdog just monitors authenticated_ flag as a backup mechanism
        LOG_INFO("WATCHDOG", ">>> start_watchdog() called, auto_exit=" + std::string(auto_exit ? "true" : "false"));
        if (!auto_exit) return;

        LOG_INFO("WATCHDOG", ">>> Creating watchdog thread");
        watchdog_thread_ = std::thread([this]() {
            LOG_INFO("WATCHDOG", ">>> Watchdog thread started");
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(2));

                if (!running_) break;

                // SECURITY CHECK #3: Redundant auth verification
                if (!quick_auth_verify()) {
                    LOG_WARN("WATCHDOG", "Auth verification failed #3, calling handle_session_killed()");
                    handle_session_killed();
                    break;
                }

                // Check if session was lost (backup mechanism)
                if (!authenticated_) {
                    LOG_WARN("WATCHDOG", "Detected lost authentication, calling handle_session_killed()");
                    handle_session_killed();
                    break;  // Exit loop after handling
                }
            }
            LOG_DEBUG("WATCHDOG", ">>> Watchdog thread exiting");
        });
    }

    // ========================================================================
    // APP VARIABLES
    // ========================================================================

    std::string get_app_var(const std::string& name) {
        json data = {{RXor("variableName"), name}};

        auto response = send_request(RXor("getAppVar"), data);

        if (response.value("success", false) && response.contains("data")) {
            if (response["data"].is_string()) {
                return response["data"].get<std::string>();
            }
            return response["data"].dump();
        }

        // Check for authentication required error
        std::string error_msg = response.value("message", response.value("error", ""));
        std::string error_lower = error_msg;
        std::transform(error_lower.begin(), error_lower.end(), error_lower.begin(), ::tolower);
        if (error_lower.find("authentication required") != std::string::npos) {
            std::cerr << "[Olivia] Variable '" << name << "' requires authentication. Use license() or login() first." << std::endl;
        }
        last_error_ = error_msg;

        return "";
    }

    std::map<std::string, std::string> get_all_app_vars() {
        std::map<std::string, std::string> result;

        auto response = send_request(RXor("getAllAppVar"), json::object());

        if (response.value("success", false) && response.contains("data") && response["data"].is_object()) {
            for (auto& [key, value] : response["data"].items()) {
                if (value.is_string()) {
                    result[key] = value.get<std::string>();
                } else {
                    result[key] = value.dump();
                }
            }
        }

        return result;
    }

    // ========================================================================
    // WEBHOOKS
    // ========================================================================

    std::string call_webhook(const std::string& webhook_id, const std::string& payload,
                             const std::string& method) {
        json data;
        try {
            data = json::parse(payload);
        } catch (...) {
            data = json::object();
        }

        json request_data = {
            {RXor("id"), webhook_id},
            {RXor("method"), method},
            {RXor("payload"), data},
            {RXor("timeout"), 30},
            {RXor("contentType"), RXor("application/json")}
        };

        auto response = send_request(RXor("webhook"), request_data);

        if (response.value("success", false) && response.contains("data")) {
            if (response["data"].is_string()) {
                return response["data"].get<std::string>();
            }
            return response["data"].dump();
        }

        // Check for authentication required error
        std::string error_msg = response.value("message", response.value("error", ""));
        std::string error_lower = error_msg;
        std::transform(error_lower.begin(), error_lower.end(), error_lower.begin(), ::tolower);
        if (error_lower.find("not authenticated") != std::string::npos ||
            error_lower.find("authentication required") != std::string::npos) {
            std::cerr << "[Olivia] Webhook '" << webhook_id << "' requires authentication. Use license() or login() first." << std::endl;
        }
        last_error_ = error_msg;

        return "";
    }
};

// ============================================================================
// PUBLIC OliviaAuth METHODS
// ============================================================================

OliviaAuth::OliviaAuth(
    const std::string& owner_id,
    const std::string& app_name,
    const std::string& version,
    const std::string& server_url,
    const std::string& client_key,
    const std::string& server_key,
    const std::string& hash_check,
    bool auto_init,
    int heartbeat_interval,
    Mode mode,
    bool auto_exit,
    const std::string& ssl_sha256
) : impl_(std::make_unique<Impl>())
{

    impl_->owner_id = owner_id;
    impl_->app_name = app_name;
    impl_->version = version;
    // Remove trailing slash from server URL
    impl_->server_url = server_url;
    while (!impl_->server_url.empty() && impl_->server_url.back() == '/') {
        impl_->server_url.pop_back();
    }
    impl_->client_key = client_key;
    impl_->server_key = server_key;
    impl_->hash_check = hash_check;
    impl_->ssl_sha256 = ssl_sha256;
    impl_->auto_init = auto_init;
    impl_->heartbeat_interval = heartbeat_interval;
    impl_->mode = mode;
    impl_->auto_exit = auto_exit;


    // Auto-initialize if requested
    if (auto_init) {
        // Call do_init() directly instead of init() to avoid throwing exceptions
        // If initialization fails, initialized_ will be false and user can check with initialized()
        impl_->do_init();
    }
}

OliviaAuth::~OliviaAuth() {
    close();
}

OliviaAuth::OliviaAuth(OliviaAuth&&) noexcept = default;
OliviaAuth& OliviaAuth::operator=(OliviaAuth&&) noexcept = default;

bool OliviaAuth::initialized() const {
    return impl_->initialized_;
}

bool OliviaAuth::authenticated() const {
    // Derived from state (matches Python line 235-238)

    #ifdef _WIN32
    // SECURITY: Multi-layer verification to prevent hooking
    // If ANY check fails, return false silently

    // Check #1: Anti-debug
    if (antidebug::is_being_debugged()) {
        return false;
    }

    // Check #2: Code integrity
    if (!integrity::verify_no_obvious_patches()) {
        return false;
    }

    // Check #3: Redundant auth verification
    if (!impl_->quick_auth_verify()) {
        return false;
    }
    #endif

    return impl_->is_authenticated();
}

bool OliviaAuth::connected() const {
    // Derived from state (matches Python line 225-232)
    return impl_->is_connected();
}

const std::string& OliviaAuth::last_error() const {
    return impl_->last_error_;
}

Mode OliviaAuth::mode() const {
    return impl_->mode;
}

ConnectionState OliviaAuth::state() const {
    return impl_->connection_state_.load();
}

const std::string& OliviaAuth::session_id() const {
    return impl_->session_id_;
}

bool OliviaAuth::init() {
    if (!impl_->do_init()) {
        impl_->throw_error(impl_->last_error_);
    }
    return true;
}

bool OliviaAuth::license(const std::string& license_key, const std::string& hwid) {
    LOG_INFO("API", ">>> OliviaAuth::license() called");
    if (!impl_->initialized_) {
        impl_->last_error_ = "App not initialized. Call init() first.";
        LOG_ERROR("API", impl_->last_error_);
        return false;
    }
    LOG_INFO("API", ">>> Calling do_license()");
    bool result = impl_->do_license(license_key, hwid);
    if (result) {
        LOG_INFO("API", ">>> do_license() returned true, returning from license()");
    } else {
        LOG_ERROR("API", ">>> do_license() failed: " + impl_->last_error_);
    }
    return result;
}

bool OliviaAuth::login(
    const std::string& username,
    const std::string& password,
    const std::string& hwid,
    const std::string& two_factor
) {
    if (!impl_->initialized_) {
        impl_->last_error_ = "App not initialized. Call init() first.";
        LOG_ERROR("API", impl_->last_error_);
        return false;
    }
    bool result = impl_->do_login(username, password, hwid, two_factor);
    if (!result) {
        LOG_ERROR("API", "Login failed: " + impl_->last_error_);
    }
    return result;
}

bool OliviaAuth::register_user(
    const std::string& license_key,
    const std::string& username,
    const std::string& password,
    const std::string& hwid
) {
    if (!impl_->initialized_) {
        impl_->last_error_ = "App not initialized. Call init() first.";
        LOG_ERROR("API", impl_->last_error_);
        return false;
    }
    bool result = impl_->do_register(license_key, username, password, hwid);
    if (!result) {
        LOG_ERROR("API", "Registration failed: " + impl_->last_error_);
    }
    return result;
}

const UserData& OliviaAuth::user() const {
    #ifdef _WIN32
    // SECURITY: Verify auth before returning user data
    if (!impl_->quick_auth_verify()) {
        static UserData empty_user;
        return empty_user;
    }
    #endif
    return impl_->user_;
}

std::string OliviaAuth::get_app_var(const std::string& name) {
    if (!impl_->initialized_) {
        impl_->last_error_ = "App not initialized. Call init() first.";
        LOG_ERROR("API", impl_->last_error_);
        return "";
    }
    // SECURITY CHECK #3: Redundant auth verification before sensitive operation
    if (!impl_->quick_auth_verify()) {
        impl_->last_error_ = impl_->get_varied_error_message(3);
        LOG_ERROR(RXor("API"), impl_->last_error_);
        return "";
    }
    return impl_->get_app_var(name);
}

std::map<std::string, std::string> OliviaAuth::get_all_app_vars() {
    if (!impl_->initialized_) {
        impl_->last_error_ = RXor("App not initialized. Call init() first.");
        LOG_ERROR(RXor("API"), impl_->last_error_);
        return {};
    }
    // SECURITY CHECK #3: Redundant auth verification before sensitive operation
    if (!impl_->quick_auth_verify()) {
        impl_->last_error_ = impl_->get_varied_error_message(3);
        LOG_ERROR(RXor("API"), impl_->last_error_);
        return {};
    }
    return impl_->get_all_app_vars();
}

bool OliviaAuth::heartbeat() {
    if (!impl_->authenticated_) return false;
    return impl_->do_heartbeat();
}

void OliviaAuth::close() {
    impl_->stop();
    impl_->authenticated_ = false;
    impl_->initialized_ = false;
}

std::string OliviaAuth::call_webhook(
    const std::string& webhook_id,
    const std::string& payload,
    const std::string& method
) {
    if (!impl_->initialized_) {
        impl_->last_error_ = "App not initialized. Call init() first.";
        LOG_ERROR("API", impl_->last_error_);
        return "";
    }
    // SECURITY CHECK #3: Redundant auth verification before sensitive operation
    if (!impl_->quick_auth_verify()) {
        impl_->last_error_ = impl_->get_varied_error_message(3);
        LOG_ERROR(RXor("API"), impl_->last_error_);
        return "";
    }
    return impl_->call_webhook(webhook_id, payload, method);
}

void OliviaAuth::on_command(const std::string& name, CommandHandler handler) {
    impl_->command_handlers_[name] = std::move(handler);
}

std::vector<std::string> OliviaAuth::get_registered_commands() const {
    std::vector<std::string> result;
    for (const auto& [name, _] : impl_->command_handlers_) {
        result.push_back(name);
    }
    return result;
}

void OliviaAuth::wait() {
    // Block until stopped
    while (impl_->running_ && impl_->authenticated_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void OliviaAuth::set_on_connect(ConnectionCallback callback) {
    impl_->on_connect_ = std::move(callback);
}

void OliviaAuth::set_on_disconnect(ConnectionCallback callback) {
    impl_->on_disconnect_ = std::move(callback);
}

void OliviaAuth::set_on_session_expired(SessionExpiredCallback callback) {
    impl_->on_session_expired_ = std::move(callback);
}

std::string OliviaAuth::get_ssl_fingerprint() {
    if (!impl_->transport_) return "";
    // Only HTTPTransport supports fingerprint retrieval
    auto* http_transport = dynamic_cast<transport::HTTPTransport*>(impl_->transport_.get());
    if (http_transport) {
        return http_transport->get_server_fingerprint();
    }
    return "";
}

std::string OliviaAuth::get_app_version() const {
    return impl_->app_version_;
}

// ============================================================================
// FILE DOWNLOADS
// ============================================================================

bool OliviaAuth::download_file(
    const std::string& download_id,
    const std::string& save_path,
    bool show_progress
) {
    try {
        // Create HTTP client
        oliviauth::http::Client cli(impl_->server_url);
        cli.set_timeout(120);

        // Set headers
        std::map<std::string, std::string> headers;

        // Add session if authenticated (for private downloads)
        if (impl_->authenticated_ && !impl_->session_id_.empty()) {
            headers[RXor("Session-ID")] = impl_->session_id_;
        }

        if (show_progress) {
            std::cout << RXor("[Olivia] Downloading...") << std::endl;
        }

        // Make request
        auto res = cli.get(std::string(RXor("/api/1.0/download/")) + download_id, headers);

        if (!res.ok() && res.status_code == 0) {
            impl_->last_error_ = RXor("Network error");
            if (show_progress) {
                std::cout << "[Olivia] " << impl_->last_error_ << std::endl;
            }
            return false;
        }

        // Handle errors
        if (res.status_code == 401) {
            impl_->last_error_ = "Authentication required. Please use license() or login() first.";
            if (show_progress) {
                std::cout << "[Olivia] " << impl_->last_error_ << std::endl;
            }
            return false;
        }

        if (res.status_code == 403) {
            // Try to parse error message from JSON
            try {
                auto json = nlohmann::json::parse(res.body);
                impl_->last_error_ = json.value("message", "Access forbidden - check your subscription status");
            } catch (...) {
                impl_->last_error_ = "Access forbidden - check your subscription status";
            }
            if (show_progress) {
                std::cout << "[Olivia] " << impl_->last_error_ << std::endl;
            }
            return false;
        }

        if (res.status_code == 404) {
            impl_->last_error_ = "Download not found or not available";
            if (show_progress) {
                std::cout << "[Olivia] " << impl_->last_error_ << std::endl;
            }
            return false;
        }

        if (res.status_code == 429) {
            try {
                auto json = nlohmann::json::parse(res.body);
                impl_->last_error_ = json.value("message", "Too many downloads - try again later");
            } catch (...) {
                impl_->last_error_ = "Too many downloads - try again later";
            }
            if (show_progress) {
                std::cout << "[Olivia] " << impl_->last_error_ << std::endl;
            }
            return false;
        }

        if (res.status_code != 200) {
            impl_->last_error_ = "Download failed: HTTP " + std::to_string(res.status_code);
            if (show_progress) {
                std::cout << "[Olivia] " << impl_->last_error_ << std::endl;
            }
            return false;
        }

        // Save file
        std::ofstream file(save_path, std::ios::binary);
        if (!file) {
            impl_->last_error_ = "Failed to create file: " + save_path;
            if (show_progress) {
                std::cout << "[Olivia] " << impl_->last_error_ << std::endl;
            }
            return false;
        }

        file.write(res.body.data(), res.body.size());
        file.close();

        if (show_progress) {
            double mb = res.body.size() / (1024.0 * 1024.0);
            std::cout << "[Olivia] Download complete: " << save_path
                      << " (" << std::fixed << std::setprecision(2) << mb << " MB)"
                      << std::endl;
        }

        impl_->last_error_.clear();
        return true;

    } catch (const std::exception& e) {
        impl_->last_error_ = std::string("Error: ") + e.what();
        if (show_progress) {
            std::cout << "[Olivia] " << impl_->last_error_ << std::endl;
        }
        return false;
    }
}

std::string OliviaAuth::get_download_info(const std::string& download_id) {
    try {
        oliviauth::http::Client cli(impl_->server_url);
        cli.set_timeout(30);

        auto res = cli.get(std::string(RXor("/api/1.0/download/")) + download_id + RXor("/info"));

        if (res.status_code != 200) {
            impl_->last_error_ = std::string(RXor("Failed to get download info: HTTP ")) +
                                 (res.status_code > 0 ? std::to_string(res.status_code) : RXor("connection error"));
            return "";
        }

        // Parse JSON response
        auto json = nlohmann::json::parse(res.body);

        if (!json.value(RXor("success"), false)) {
            impl_->last_error_ = json.value(RXor("message"), RXor("Failed to get download info"));
            return "";
        }

        // Return the download info as JSON string
        return json["download"].dump();

    } catch (const std::exception& e) {
        impl_->last_error_ = std::string("Error: ") + e.what();
        return "";
    }
}

bool OliviaAuth::quick_download(
    const std::string& server_url,
    const std::string& download_id,
    const std::string& save_path,
    bool show_progress
) {
    try {
        oliviauth::http::Client cli(server_url);
        cli.set_timeout(120);

        if (show_progress) {
            std::cout << RXor("[Olivia] Downloading...") << std::endl;
        }

        auto res = cli.get(std::string(RXor("/api/1.0/download/")) + download_id);

        if (!res.ok() && res.status_code == 0) {
            if (show_progress) {
                std::cout << RXor("[Olivia] Network error") << std::endl;
            }
            return false;
        }

        if (res.status_code == 401) {
            if (show_progress) {
                std::cout << RXor("[Olivia] This is a private download - authentication required") << std::endl;
                std::cout << RXor("[Olivia] Use the regular download_file() method after logging in") << std::endl;
            }
            return false;
        }

        if (res.status_code == 429) {
            if (show_progress) {
                std::cout << "[Olivia] Rate limit exceeded - try again later" << std::endl;
            }
            return false;
        }

        if (res.status_code != 200) {
            if (show_progress) {
                std::cout << "[Olivia] Download failed: HTTP " << res.status_code << std::endl;
            }
            return false;
        }

        // Save file
        std::ofstream file(save_path, std::ios::binary);
        if (!file) {
            if (show_progress) {
                std::cout << "[Olivia] Failed to create file: " << save_path << std::endl;
            }
            return false;
        }

        file.write(res.body.data(), res.body.size());
        file.close();

        if (show_progress) {
            double mb = res.body.size() / (1024.0 * 1024.0);
            std::cout << "[Olivia] Download complete: " << save_path
                      << " (" << std::fixed << std::setprecision(2) << mb << " MB)"
                      << std::endl;
        }

        return true;

    } catch (const std::exception& e) {
        if (show_progress) {
            std::cout << "[Olivia] Error: " << e.what() << std::endl;
        }
        return false;
    }
}

// ============================================================================
// PUBLIC HWID UTILITY FUNCTIONS (wrappers)
// ============================================================================

std::string get_mac_address() {
    return hwid::get_mac_address();
}

std::string get_hostname() {
    return hwid::get_hostname();
}

std::string get_system_info() {
    return hwid::get_system_info();
}

std::string get_cpu_id() {
    return hwid::get_cpu_id();
}

std::string get_disk_serial() {
    return hwid::get_disk_serial();
}

std::string get_machine_guid() {
    return hwid::get_machine_guid();
}

// ============================================================================
// PUBLIC CRYPTO NAMESPACE (wrappers)
// ============================================================================

namespace crypto {

RSAKeyPair* generate_rsa_keypair() {
    return oliviauth::crypto::generate_keypair();
}

void free_rsa_keypair(RSAKeyPair* keypair) {
    oliviauth::crypto::free_keypair(keypair);
}

std::string serialize_public_key(const RSAKeyPair* keypair) {
    return oliviauth::crypto::get_public_key_pem(keypair);
}

RSAKeyPair* load_public_key(const std::string& pem_data) {
    return oliviauth::crypto::load_public_key_pem(pem_data);
}

std::vector<uint8_t> encrypt_with_rsa(
    const std::vector<uint8_t>& data,
    const RSAKeyPair* public_key
) {
    return oliviauth::crypto::rsa_encrypt(data, public_key);
}

std::vector<uint8_t> decrypt_with_rsa(
    const std::vector<uint8_t>& encrypted_data,
    const RSAKeyPair* private_key
) {
    return oliviauth::crypto::rsa_decrypt(encrypted_data, private_key);
}

std::vector<uint8_t> encrypt_aes_gcm(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key
) {
    return oliviauth::crypto::aes_gcm_encrypt(plaintext, key);
}

std::vector<uint8_t> decrypt_aes_gcm(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key
) {
    return oliviauth::crypto::aes_gcm_decrypt(ciphertext, key);
}

std::vector<uint8_t> generate_aes_key() {
    return oliviauth::crypto::random_bytes(AES_KEY_SIZE);
}

// Note: xor_obfuscate, xor_deobfuscate, base64_encode, base64_decode,
// base64url_encode, base64url_decode, random_bytes are already defined
// in crypto.cpp with the same signatures - no wrappers needed.

std::string sha256(const std::string& data) {
    return oliviauth::crypto::sha256_hex(data);
}

std::vector<uint8_t> sha256_bytes(const std::vector<uint8_t>& data) {
    return oliviauth::crypto::sha256(data);
}

} // namespace crypto

} // namespace oliviauth
