/**
 * @file oliviauth.h
 * @brief Olivia Auth C++ SDK - Single header for complete authentication system
 *
 * This is the ONLY header the user needs to include.
 *
 * Usage:
 *   #include <oliviauth.h>
 *
 *   oliviauth::OliviaAuth api("owner", "app", "1.0", "url", "client_key", "server_key");
 *   if (api.license("XXXX-XXXX")) {
 *       std::cout << "Welcome " << api.user().username << std::endl;
 *   }
 */

#pragma once

#ifdef _WIN32
    #ifdef OLIVIAUTH_EXPORTS
        #define OLIVIAUTH_API __declspec(dllexport)
    #else
        #define OLIVIAUTH_API
    #endif
#else
    #define OLIVIAUTH_API
#endif

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <functional>
#include <optional>
#include <cstdint>
#include <stdexcept>

namespace oliviauth {

// ============================================================================
// EXCEPTION HIERARCHY (matches Python SDK)
// ============================================================================

/**
 * @brief Base exception for all OliviaAuth errors
 */
class OLIVIAUTH_API OliviaAuthError : public std::runtime_error {
public:
    explicit OliviaAuthError(const std::string& message = "OliviaAuth error")
        : std::runtime_error(message) {}
};

/**
 * @brief Thrown when client is not initialized
 */
class OLIVIAUTH_API NotInitializedError : public OliviaAuthError {
public:
    explicit NotInitializedError(const std::string& message = "App not initialized. Call init() first.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown when session has expired
 */
class OLIVIAUTH_API SessionExpiredError : public OliviaAuthError {
public:
    explicit SessionExpiredError(const std::string& message = "Session has expired. Please reinitialize.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown when authentication fails
 */
class OLIVIAUTH_API AuthenticationError : public OliviaAuthError {
public:
    explicit AuthenticationError(const std::string& message = "Authentication failed.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown when not authenticated
 */
class OLIVIAUTH_API NotAuthenticatedError : public OliviaAuthError {
public:
    explicit NotAuthenticatedError(const std::string& message = "Not authenticated. Use license() or login() first.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown on encryption/decryption errors
 */
class OLIVIAUTH_API EncryptionError : public OliviaAuthError {
public:
    explicit EncryptionError(const std::string& message = "Encryption error occurred.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown on connection errors
 */
class OLIVIAUTH_API ConnectionError : public OliviaAuthError {
public:
    explicit ConnectionError(const std::string& message = "Failed to connect to server.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown when HWID does not match
 */
class OLIVIAUTH_API HWIDMismatchError : public OliviaAuthError {
public:
    explicit HWIDMismatchError(const std::string& message = "HWID mismatch. Ask for a reset.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown when subscription has expired
 */
class OLIVIAUTH_API SubscriptionExpiredError : public OliviaAuthError {
public:
    explicit SubscriptionExpiredError(const std::string& message = "Your subscription has expired.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown when 2FA is required
 */
class OLIVIAUTH_API TwoFactorRequiredError : public OliviaAuthError {
public:
    explicit TwoFactorRequiredError(const std::string& message = "Two-factor authentication code required.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown when user is banned
 */
class OLIVIAUTH_API UserBannedError : public OliviaAuthError {
public:
    explicit UserBannedError(const std::string& message = "User is banned.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown when app is disabled
 */
class OLIVIAUTH_API AppDisabledError : public OliviaAuthError {
public:
    explicit AppDisabledError(const std::string& message = "App is currently disabled.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown when version does not match
 */
class OLIVIAUTH_API VersionMismatchError : public OliviaAuthError {
public:
    explicit VersionMismatchError(const std::string& message = "Version mismatch. Update required.")
        : OliviaAuthError(message) {}
};

/**
 * @brief Thrown when VPN/Proxy is detected and blocked
 */
class OLIVIAUTH_API VPNBlockedError : public OliviaAuthError {
public:
    explicit VPNBlockedError(const std::string& message = "VPN/Proxy detected. Please disable.")
        : OliviaAuthError(message) {}
};

// ============================================================================
// ENUMS
// ============================================================================

/**
 * @brief Connection mode
 */
enum class Mode {
    Socket,  ///< WebSocket mode (default) - Real-time, supports remote commands
    Http     ///< HTTP mode - Traditional REST requests
};

/**
 * @brief WebSocket connection states (matches Python SDK)
 */
enum class ConnectionState {
    DISCONNECTED,    ///< No socket connection
    CONNECTING,      ///< Attempting to connect
    CONNECTED,       ///< Socket connected, session not authenticated
    AUTHENTICATING,  ///< Sending session_id to server
    AUTHENTICATED    ///< Fully operational
};

// ============================================================================
// USER DATA CLASS
// ============================================================================

/**
 * @brief User data returned after successful authentication
 *
 * Contains all user information including subscriptions, variables, and metadata.
 */
class OLIVIAUTH_API UserData {
public:
    UserData();
    explicit UserData(const std::string& json_data);
    ~UserData();

    // Copy and move operations
    UserData(const UserData& other);
    UserData& operator=(const UserData& other);
    UserData(UserData&&) noexcept;
    UserData& operator=(UserData&&) noexcept;

    // Basic user info
    std::string username;           ///< Username
    std::string hwid;               ///< Hardware ID
    std::string ip;                 ///< IP address
    int64_t create_date = 0;        ///< Account creation timestamp (Unix)
    int64_t last_login = 0;         ///< Last login timestamp (Unix)

    // User variables
    std::map<std::string, std::string> variables;

    // ========================================================================
    // SUBSCRIPTION METHODS (same as Python)
    // ========================================================================

    /**
     * @brief Check if user has an active subscription
     * @param level Subscription level (empty = any level)
     * @return true if has active subscription
     */
    bool has_subscription(const std::string& level = "") const;

    /**
     * @brief Check if subscription is lifetime
     * @param level Subscription level
     * @return true if lifetime
     */
    bool is_lifetime(const std::string& level) const;

    /**
     * @brief Get subscription name
     * @param level Subscription level
     * @return Subscription name or empty string
     */
    std::string get_subscription_name(const std::string& level) const;

    /**
     * @brief Get subscription expiry timestamp
     * @param level Subscription level
     * @return Unix timestamp or -1 for lifetime, 0 if not found
     */
    int64_t get_subscription_expiry(const std::string& level) const;

    /**
     * @brief Get time left in seconds
     * @param level Subscription level
     * @return Seconds remaining, -1 for lifetime, 0 if expired/not found
     */
    int64_t get_subscription_time_left(const std::string& level) const;

    /**
     * @brief Get formatted time left string
     * @param level Subscription level (empty = first active)
     * @return Formatted string like "30 days" or "Lifetime"
     */
    std::string format_time_left(const std::string& level = "") const;

    /**
     * @brief Get all active subscription levels
     * @return Vector of level IDs
     */
    std::vector<std::string> get_active_subscription_levels() const;

    /**
     * @brief Get all subscription names
     * @return Map of level -> name
     */
    std::map<std::string, std::string> get_all_subscription_names() const;

    /**
     * @brief Get user variable
     * @param name Variable name
     * @param default_value Default if not found
     * @return Variable value or default
     */
    std::string get_variable(const std::string& name, const std::string& default_value = "") const;

    /**
     * @brief Check if user data is valid
     */
    bool is_valid() const;

    /**
     * @brief Get raw JSON data
     */
    const std::string& raw_json() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// COMMAND HANDLER TYPE
// ============================================================================

/**
 * @brief Command handler function type
 * @param params JSON parameters as string
 * @return JSON response as string
 */
using CommandHandler = std::function<std::string(const std::string& params)>;

// ============================================================================
// CALLBACKS
// ============================================================================

/**
 * @brief Callback for connection events
 */
using ConnectionCallback = std::function<void()>;

/**
 * @brief Callback for session expired event
 */
using SessionExpiredCallback = std::function<void()>;

// ============================================================================
// MAIN CLASS: OliviaAuth
// ============================================================================

/**
 * @brief Main Olivia Auth client class
 *
 * This is the primary interface for authentication. It handles:
 * - License/Login/Register authentication
 * - Automatic heartbeat (keeps session alive)
 * - Automatic watchdog (exits app if session lost)
 * - Remote commands (WebSocket only)
 * - Encryption (RSA-2048 + AES-256-GCM + XOR)
 *
 * @example
 * oliviauth::OliviaAuth api("owner", "app", "1.0", "https://server.com", "key1", "key2");
 * if (api.license("XXXX-XXXX")) {
 *     std::cout << "Welcome " << api.user().username << std::endl;
 * }
 */
class OLIVIAUTH_API OliviaAuth {
public:
    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    /**
     * @brief Construct OliviaAuth client (Python-compatible signature)
     *
     * @param owner_id Your owner ID from dashboard (REQUIRED)
     * @param app_name Application name (REQUIRED)
     * @param version Application version (REQUIRED)
     * @param server_url Server URL (default: "https://api.oliviauth.xyz")
     * @param client_key Client obfuscation key (optional but recommended)
     * @param server_key Server obfuscation key (optional but recommended)
     * @param hash_check Hash for loader integrity verification (optional)
     * @param auto_init Auto-initialize on construction (default: true)
     * @param heartbeat_interval Heartbeat interval in seconds (default: 60)
     * @param mode Connection mode: Socket (default) or Http
     * @param auto_exit Auto-exit if session lost (default: true)
     * @param ssl_sha256 Expected SSL certificate SHA256 fingerprint for pinning (optional)
     */
    OliviaAuth(
        const std::string& owner_id,
        const std::string& app_name,
        const std::string& version,
        const std::string& server_url = "https://api.oliviauth.xyz",
        const std::string& client_key = "",
        const std::string& server_key = "",
        const std::string& hash_check = "",
        bool auto_init = true,
        int heartbeat_interval = 60,
        Mode mode = Mode::Socket,
        bool auto_exit = true,
        const std::string& ssl_sha256 = ""
    );

    /**
     * @brief Destructor - cleans up threads and connections
     */
    ~OliviaAuth();

    // Move only (no copy)
    OliviaAuth(const OliviaAuth&) = delete;
    OliviaAuth& operator=(const OliviaAuth&) = delete;
    OliviaAuth(OliviaAuth&&) noexcept;
    OliviaAuth& operator=(OliviaAuth&&) noexcept;

    // ========================================================================
    // STATE PROPERTIES
    // ========================================================================

    /**
     * @brief Check if client is initialized
     * @return true if init() succeeded
     */
    bool initialized() const;

    /**
     * @brief Check if user is authenticated
     * @return true if license/login succeeded
     */
    bool authenticated() const;

    /**
     * @brief Check if connected (WebSocket only)
     * @return true if WebSocket connected
     */
    bool connected() const;

    /**
     * @brief Get last error message
     * @return Error message or empty string
     */
    const std::string& last_error() const;

    /**
     * @brief Get current mode
     * @return Mode::Socket or Mode::Http
     */
    Mode mode() const;

    /**
     * @brief Get current connection state (matches Python SDK)
     * @return Current ConnectionState
     */
    ConnectionState state() const;

    /**
     * @brief Get session ID
     * @return Current session ID or empty
     */
    const std::string& session_id() const;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    /**
     * @brief Initialize connection to server
     *
     * Creates session, exchanges keys, and validates app.
     * Called automatically if auto_init=true.
     *
     * @return true on success
     */
    bool init();

    // ========================================================================
    // AUTHENTICATION METHODS
    // ========================================================================

    /**
     * @brief Authenticate with license key
     *
     * @param license_key The license key
     * @param hwid Hardware ID (empty = auto-generate)
     * @return true on success
     */
    bool license(const std::string& license_key, const std::string& hwid = "");

    /**
     * @brief Authenticate with username/password
     *
     * @param username Username
     * @param password Password
     * @param hwid Hardware ID (empty = auto-generate)
     * @param two_factor 2FA code if required (empty = none)
     * @return true on success
     */
    bool login(
        const std::string& username,
        const std::string& password,
        const std::string& hwid = "",
        const std::string& two_factor = ""
    );

    /**
     * @brief Register new user
     *
     * @param license_key License key to bind
     * @param username New username
     * @param password New password
     * @param hwid Hardware ID (empty = auto-generate)
     * @return true on success
     */
    bool register_user(
        const std::string& license_key,
        const std::string& username,
        const std::string& password,
        const std::string& hwid = ""
    );

    // ========================================================================
    // USER DATA
    // ========================================================================

    /**
     * @brief Get user data (after authentication)
     * @return Reference to UserData object
     */
    const UserData& user() const;

    // ========================================================================
    // APP VARIABLES
    // ========================================================================

    /**
     * @brief Get single app variable
     * @param name Variable name
     * @return Variable value or empty string
     */
    std::string get_app_var(const std::string& name);

    /**
     * @brief Get all app variables
     * @return Map of name -> value
     */
    std::map<std::string, std::string> get_all_app_vars();

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    /**
     * @brief Send manual heartbeat
     *
     * Normally called automatically by background thread.
     *
     * @return true on success
     */
    bool heartbeat();

    /**
     * @brief Close connection and cleanup
     *
     * Stops heartbeat, watchdog, and disconnects.
     */
    void close();

    // ========================================================================
    // WEBHOOKS
    // ========================================================================

    /**
     * @brief Call custom webhook
     *
     * @param webhook_id Webhook ID from dashboard
     * @param payload JSON payload (optional)
     * @param method HTTP method (default: POST)
     * @return Response data as string, or empty on error
     */
    std::string call_webhook(
        const std::string& webhook_id,
        const std::string& payload = "{}",
        const std::string& method = "POST"
    );

    // ========================================================================
    // REMOTE COMMANDS (WebSocket only)
    // ========================================================================

    /**
     * @brief Register command handler
     *
     * @param name Command name
     * @param handler Handler function
     */
    void on_command(const std::string& name, CommandHandler handler);

    /**
     * @brief Get registered command names
     * @return Vector of command names
     */
    std::vector<std::string> get_registered_commands() const;

    /**
     * @brief Block and wait for commands
     *
     * Blocks the calling thread and processes incoming commands.
     * Only exits when close() is called or session expires.
     */
    void wait();

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    /**
     * @brief Set callback for connection event
     */
    void set_on_connect(ConnectionCallback callback);

    /**
     * @brief Set callback for disconnection event
     */
    void set_on_disconnect(ConnectionCallback callback);

    /**
     * @brief Set callback for session expired (before auto-exit)
     */
    void set_on_session_expired(SessionExpiredCallback callback);

    // ========================================================================
    // FILE DOWNLOADS
    // ========================================================================

    /**
     * @brief Download a file by ID
     *
     * Supports both PUBLIC and PRIVATE downloads:
     * - PUBLIC: No authentication needed
     * - PRIVATE: Requires authenticated session with valid subscription
     *
     * If authenticated, automatically uses session for private downloads.
     *
     * @param download_id Download ID from server/dashboard
     * @param save_path Where to save the file (e.g., "update.zip")
     * @param show_progress Show download progress (default: true)
     * @return true if successful
     *
     * @example
     * // Download after authentication (works for private files)
     * api.license("XXXX-XXXX");
     * api.download_file("abc123", "update.zip");
     *
     * @example
     * // Download public file (no login needed)
     * api.download_file("xyz789", "public.zip");
     */
    bool download_file(
        const std::string& download_id,
        const std::string& save_path,
        bool show_progress = true
    );

    /**
     * @brief Get download metadata without downloading
     *
     * @param download_id Download ID
     * @return JSON string with info (name, fileSize, authenticated, etc.) or empty on error
     *
     * @example
     * std::string info = api.get_download_info("abc123");
     * // Parse JSON to check if authenticated, size, etc.
     */
    std::string get_download_info(const std::string& download_id);

    /**
     * @brief Quick download for PUBLIC files (static method)
     *
     * Download without creating a session. For PRIVATE files, use
     * the regular download_file() method after authentication.
     *
     * @param server_url Server URL (e.g., "https://api.oliviauth.xyz")
     * @param download_id Download ID
     * @param save_path Where to save the file
     * @param show_progress Show progress bar
     * @return true if successful
     *
     * @example
     * OliviaAuth::quick_download(
     *     "https://api.oliviauth.xyz",
     *     "download123",
     *     "update.zip"
     * );
     */
    static bool quick_download(
        const std::string& server_url,
        const std::string& download_id,
        const std::string& save_path,
        bool show_progress = true
    );

    // ========================================================================
    // UTILITY
    // ========================================================================

    /**
     * @brief Get SSL fingerprint of server
     * @return SHA256 fingerprint or empty
     */
    std::string get_ssl_fingerprint();

    /**
     * @brief Get app info from server
     * @return App version from server or empty
     */
    std::string get_app_version() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// DEBUG MODE
// ============================================================================

/**
 * @brief Log level for debug output
 */
enum class LogLevel {
    None = 0,    ///< No logging (default)
    Error = 1,   ///< Only errors
    Warning = 2, ///< Errors and warnings
    Info = 3,    ///< Errors, warnings, and info
    Debug = 4    ///< All messages including debug
};

/**
 * @brief Enable or disable debug mode
 * @param enabled true to enable debug output to console
 *
 * When enabled, the SDK will print detailed information about:
 * - Connection attempts and status
 * - Authentication flow
 * - Errors and their details
 * - Request/response summaries (not sensitive data)
 */
OLIVIAUTH_API void set_debug_mode(bool enabled);

/**
 * @brief Set the log level for debug output
 * @param level The minimum log level to display
 */
OLIVIAUTH_API void set_log_level(LogLevel level);

/**
 * @brief Check if debug mode is enabled
 * @return true if debug mode is on
 */
OLIVIAUTH_API bool is_debug_mode();

/**
 * @brief Get current log level
 * @return Current log level
 */
OLIVIAUTH_API LogLevel get_log_level();

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Generate hardware ID for this machine
 *
 * Creates a unique identifier based on:
 * - CPU ID
 * - MAC address
 * - Disk serial
 * - Machine GUID
 *
 * @return SHA256 hash of hardware identifiers
 */
OLIVIAUTH_API std::string generate_hwid();

/**
 * @brief Validate HWID format
 * @param hwid HWID to validate
 * @param min_length Minimum length (default: 10)
 * @return true if valid
 */
OLIVIAUTH_API bool validate_hwid(const std::string& hwid, size_t min_length = 10);

/**
 * @brief Get SDK version
 * @return Version string
 */
OLIVIAUTH_API const char* get_sdk_version();

// ============================================================================
// HWID UTILITY FUNCTIONS (matches Python SDK)
// ============================================================================

/**
 * @brief Get MAC address of primary network interface
 * @return MAC address (uppercase, no separators) or empty string on error
 */
OLIVIAUTH_API std::string get_mac_address();

/**
 * @brief Get machine hostname
 * @return Hostname or empty string on error
 */
OLIVIAUTH_API std::string get_hostname();

/**
 * @brief Get system information string
 * @return System info (e.g., "Linux-x86_64") or empty string on error
 */
OLIVIAUTH_API std::string get_system_info();

/**
 * @brief Get CPU identifier
 * @return CPU ID string or empty string on error
 */
OLIVIAUTH_API std::string get_cpu_id();

/**
 * @brief Get disk serial number
 * @return Disk serial or empty string on error
 */
OLIVIAUTH_API std::string get_disk_serial();

/**
 * @brief Get machine unique identifier (GUID/UUID)
 * @return Machine GUID or empty string on error
 */
OLIVIAUTH_API std::string get_machine_guid();

// ============================================================================
// CRYPTO NAMESPACE (matches Python SDK)
// ============================================================================

namespace crypto {

// Constants
constexpr size_t AES_KEY_SIZE = 32;          ///< 256 bits
constexpr size_t AES_GCM_NONCE_SIZE = 12;    ///< 96 bits (GCM standard)
constexpr size_t RSA_KEY_SIZE = 2048;

// ========================================================================
// RSA FUNCTIONS
// ========================================================================

/**
 * @brief Opaque RSA key pair handle
 */
struct RSAKeyPair;

/**
 * @brief Generate new RSA-2048 key pair
 * @return Key pair handle (must be freed with free_rsa_keypair)
 */
OLIVIAUTH_API RSAKeyPair* generate_rsa_keypair();

/**
 * @brief Free RSA key pair
 * @param keypair Key pair to free
 */
OLIVIAUTH_API void free_rsa_keypair(RSAKeyPair* keypair);

/**
 * @brief Serialize public key to PEM format
 * @param keypair Key pair
 * @return PEM-encoded public key
 */
OLIVIAUTH_API std::string serialize_public_key(const RSAKeyPair* keypair);

/**
 * @brief Load public key from PEM data
 * @param pem_data PEM-encoded public key
 * @return Key pair handle or nullptr on error
 */
OLIVIAUTH_API RSAKeyPair* load_public_key(const std::string& pem_data);

/**
 * @brief Encrypt data with RSA-OAEP (SHA-256)
 * @param data Data to encrypt
 * @param public_key Public key
 * @return Encrypted data
 */
OLIVIAUTH_API std::vector<uint8_t> encrypt_with_rsa(
    const std::vector<uint8_t>& data,
    const RSAKeyPair* public_key
);

/**
 * @brief Decrypt data with RSA-OAEP (SHA-256)
 * @param encrypted_data Encrypted data
 * @param private_key Private key
 * @return Decrypted data
 */
OLIVIAUTH_API std::vector<uint8_t> decrypt_with_rsa(
    const std::vector<uint8_t>& encrypted_data,
    const RSAKeyPair* private_key
);

// ========================================================================
// AES-GCM FUNCTIONS
// ========================================================================

/**
 * @brief Encrypt data with AES-256-GCM
 * @param plaintext Data to encrypt
 * @param key 32-byte AES key
 * @return Encrypted data (nonce + ciphertext + tag)
 */
OLIVIAUTH_API std::vector<uint8_t> encrypt_aes_gcm(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key
);

/**
 * @brief Decrypt data with AES-256-GCM
 * @param ciphertext Encrypted data (nonce + ciphertext + tag)
 * @param key 32-byte AES key
 * @return Decrypted data or empty on failure
 */
OLIVIAUTH_API std::vector<uint8_t> decrypt_aes_gcm(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key
);

/**
 * @brief Generate random AES-256 key
 * @return 32 random bytes
 */
OLIVIAUTH_API std::vector<uint8_t> generate_aes_key();

// ========================================================================
// XOR OBFUSCATION
// ========================================================================

/**
 * @brief XOR obfuscate a string
 * @param data Data to obfuscate
 * @param key Obfuscation key
 * @return Base64-encoded obfuscated data
 */
OLIVIAUTH_API std::string xor_obfuscate(const std::string& data, const std::string& key);

/**
 * @brief XOR deobfuscate a string
 * @param data Base64-encoded obfuscated data
 * @param key Obfuscation key
 * @return Deobfuscated data
 */
OLIVIAUTH_API std::string xor_deobfuscate(const std::string& data, const std::string& key);

// ========================================================================
// HASHING
// ========================================================================

/**
 * @brief Compute SHA-256 hash
 * @param data Data to hash
 * @return Hex-encoded SHA-256 hash
 */
OLIVIAUTH_API std::string sha256(const std::string& data);

/**
 * @brief Compute SHA-256 hash (bytes)
 * @param data Data to hash
 * @return SHA-256 hash bytes
 */
OLIVIAUTH_API std::vector<uint8_t> sha256_bytes(const std::vector<uint8_t>& data);

// ========================================================================
// BASE64
// ========================================================================

/**
 * @brief Base64 encode
 * @param data Data to encode
 * @return Base64-encoded string
 */
OLIVIAUTH_API std::string base64_encode(const std::vector<uint8_t>& data);

/**
 * @brief Base64 decode
 * @param encoded Base64-encoded string
 * @return Decoded data
 */
OLIVIAUTH_API std::vector<uint8_t> base64_decode(const std::string& encoded);

/**
 * @brief Base64 URL-safe encode
 * @param data Data to encode
 * @return Base64 URL-safe encoded string
 */
OLIVIAUTH_API std::string base64url_encode(const std::vector<uint8_t>& data);

/**
 * @brief Base64 URL-safe decode
 * @param encoded Base64 URL-safe encoded string
 * @return Decoded data
 */
OLIVIAUTH_API std::vector<uint8_t> base64url_decode(const std::string& encoded);

// ========================================================================
// RANDOM
// ========================================================================

/**
 * @brief Generate cryptographically secure random bytes
 * @param length Number of bytes
 * @return Random bytes
 */
OLIVIAUTH_API std::vector<uint8_t> random_bytes(size_t length);

} // namespace crypto

} // namespace oliviauth
