#pragma once

/**
 * @file http_transport.h
 * @brief HTTP transport implementation using existing http::Client
 */

#include "transport.h"
#include "../http.h"
#include <atomic>

namespace oliviauth {
namespace transport {

/**
 * @brief HTTP-based transport implementation
 *
 * Wraps the existing http::Client to implement the Transport interface.
 * This allows HTTP mode to work seamlessly with the transport abstraction.
 */
class HTTPTransport : public Transport {
public:
    /**
     * @brief Construct HTTP transport
     * @param server_url Server URL (e.g., "https://api.oliviauth.xyz")
     */
    explicit HTTPTransport(const std::string& server_url);

    ~HTTPTransport() override;

    // Non-copyable
    HTTPTransport(const HTTPTransport&) = delete;
    HTTPTransport& operator=(const HTTPTransport&) = delete;

    // ========================================================================
    // CONNECTION LIFECYCLE
    // ========================================================================

    bool connect() override;
    void disconnect() override;
    bool is_connected() const override;

    // ========================================================================
    // REQUEST/RESPONSE
    // ========================================================================

    Response send_request(
        const std::string& endpoint,
        const std::string& body,
        const std::map<std::string, std::string>& headers = {},
        int timeout_ms = 30000
    ) override;

    // ========================================================================
    // EVENT SYSTEM (NO-OP FOR HTTP)
    // ========================================================================

    void on_event(const std::string& event, EventCallback callback) override;
    void emit(const std::string& event, const std::string& data) override;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void set_timeout(int seconds) override;
    std::string get_session_id() const override;
    void set_session_id(const std::string& session_id) override;
    std::string get_server_url() const override;
    std::string get_last_error() const override;

    // ========================================================================
    // HTTP-SPECIFIC METHODS
    // ========================================================================

    /**
     * @brief Set SSL verification
     * @param verify Enable/disable verification
     */
    void set_ssl_verify(bool verify);

    /**
     * @brief Set expected SSL fingerprint (SHA256)
     * @param fingerprint Hex-encoded SHA256 fingerprint
     */
    void set_ssl_fingerprint(const std::string& fingerprint);

    /**
     * @brief Get server SSL certificate fingerprint
     * @return SHA256 fingerprint or empty on error
     */
    std::string get_server_fingerprint();

    /**
     * @brief Verify SSL certificate fingerprint matches expected
     * @param expected_fingerprint Expected SHA256 fingerprint (hex lowercase)
     * @return true if matches or empty fingerprint
     * @throws std::runtime_error if fingerprint doesn't match
     */
    bool verify_ssl_fingerprint(const std::string& expected_fingerprint);

    /**
     * @brief Get underlying HTTP client (for advanced use)
     */
    http::Client* get_http_client();

private:
    std::string server_url_;
    std::string session_id_;
    std::string last_error_;
    std::string expected_ssl_fingerprint_;  // For SSL pinning on each request
    std::unique_ptr<http::Client> http_client_;
    std::atomic<bool> connected_{false};
    int timeout_seconds_ = 30;
};

} // namespace transport
} // namespace oliviauth
