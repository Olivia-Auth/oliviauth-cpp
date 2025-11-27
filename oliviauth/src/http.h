/**
 * @file http.h
 * @brief Internal HTTP client for Olivia Auth
 *
 * DO NOT include this file directly. Use oliviauth.h instead.
 */

#pragma once

#include <string>
#include <map>
#include <optional>
#include <memory>

namespace oliviauth {
namespace http {

/**
 * @brief HTTP response structure
 */
struct Response {
    int status_code = 0;        ///< HTTP status code (200, 404, etc.)
    std::string body;           ///< Response body
    std::string error;          ///< Error message if any
    std::map<std::string, std::string> headers;  ///< Response headers

    bool ok() const { return status_code >= 200 && status_code < 300; }
};

/**
 * @brief HTTP client class
 */
class Client {
public:
    /**
     * @brief Construct HTTP client
     * @param base_url Base URL (e.g., "https://api.oliviauth.xyz")
     */
    explicit Client(const std::string& base_url);

    ~Client();

    // Non-copyable
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    /**
     * @brief Set connection timeout
     * @param seconds Timeout in seconds
     */
    void set_timeout(int seconds);

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
     * @brief Add default header
     * @param name Header name
     * @param value Header value
     */
    void set_header(const std::string& name, const std::string& value);

    /**
     * @brief Remove default header
     * @param name Header name
     */
    void remove_header(const std::string& name);

    /**
     * @brief POST request with JSON body
     * @param endpoint Endpoint path (e.g., "/api/1.0/license")
     * @param json_body JSON body string
     * @param extra_headers Additional headers for this request
     * @return Response
     */
    Response post(
        const std::string& endpoint,
        const std::string& json_body,
        const std::map<std::string, std::string>& extra_headers = {}
    );

    /**
     * @brief GET request
     * @param endpoint Endpoint path
     * @param extra_headers Additional headers for this request
     * @return Response
     */
    Response get(
        const std::string& endpoint,
        const std::map<std::string, std::string>& extra_headers = {}
    );

    /**
     * @brief Get server SSL certificate fingerprint
     * @return SHA256 fingerprint or empty on error
     */
    std::string get_server_fingerprint();

    /**
     * @brief Verify SSL certificate fingerprint matches expected
     * @param expected_fingerprint Expected SHA256 fingerprint (hex lowercase)
     * @return true if matches or no fingerprint set, false if mismatch
     * @throws std::runtime_error if fingerprint doesn't match
     */
    bool verify_ssl_fingerprint(const std::string& expected_fingerprint);

    /**
     * @brief Get last error message
     */
    const std::string& last_error() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace http
} // namespace oliviauth
