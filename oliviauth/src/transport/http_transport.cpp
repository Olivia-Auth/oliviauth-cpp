/**
 * @file http_transport.cpp
 * @brief HTTP transport implementation using existing http::Client
 */

#include "http_transport.h"
#include "socketio_transport.h"
#include "../xor.h"
#include <sstream>
#include <iostream>

namespace oliviauth {
namespace transport {

HTTPTransport::HTTPTransport(const std::string& server_url)
    : server_url_(server_url)
{
    std::cerr << "[HTTP_TRANSPORT] Constructor, url=" << server_url << std::endl;
}

HTTPTransport::~HTTPTransport() {
    disconnect();
}

// ============================================================================
// CONNECTION LIFECYCLE
// ============================================================================

bool HTTPTransport::connect() {
    std::cerr << "[HTTP_TRANSPORT] connect() called" << std::endl;
    if (connected_) {
        return true;
    }

    try {
        std::cerr << "[HTTP_TRANSPORT] Creating http::Client..." << std::endl;
        http_client_ = std::make_unique<http::Client>(server_url_);
        std::cerr << "[HTTP_TRANSPORT] Setting timeout..." << std::endl;
        http_client_->set_timeout(timeout_seconds_);
        std::cerr << "[HTTP_TRANSPORT] Connected!" << std::endl;
        connected_ = true;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[HTTP_TRANSPORT] Exception: " << e.what() << std::endl;
        last_error_ = std::string("Failed to create HTTP client: ") + e.what();
        return false;
    }
}

void HTTPTransport::disconnect() {
    http_client_.reset();
    connected_ = false;
}

bool HTTPTransport::is_connected() const {
    return connected_;
}

// ============================================================================
// REQUEST/RESPONSE
// ============================================================================

Response HTTPTransport::send_request(
    const std::string& endpoint,
    const std::string& body,
    const std::map<std::string, std::string>& headers,
    int timeout_ms
) {
    Response response;

    if (!connected_ || !http_client_) {
        response.success = false;
        response.error = "Not connected";
        last_error_ = response.error;
        return response;
    }

    // Build full endpoint path
    std::string full_endpoint = std::string(RXor("/api/1.0/")) + endpoint;

    // Merge headers with session ID if set
    std::map<std::string, std::string> request_headers = headers;
    if (!session_id_.empty() && request_headers.find(RXor("Session-ID")) == request_headers.end()) {
        request_headers[RXor("Session-ID")] = session_id_;
    }

    // Make the POST request
    try {
        auto http_response = http_client_->post(full_endpoint, body, request_headers);

        response.status_code = http_response.status_code;
        response.body = http_response.body;
        response.success = true;

        if (!http_response.ok()) {
            response.error = http_response.error;
            if (response.error.empty()) {
                std::ostringstream oss;
                oss << "HTTP " << http_response.status_code;
                response.error = oss.str();
            }
        }
    } catch (const std::exception& e) {
        response.success = false;
        response.error = e.what();
        last_error_ = response.error;
    }

    return response;
}

// ============================================================================
// EVENT SYSTEM (NO-OP FOR HTTP)
// ============================================================================

void HTTPTransport::on_event(const std::string& /*event*/, EventCallback /*callback*/) {
    // No-op for HTTP transport
    // Events are only supported in Socket.IO mode
}

void HTTPTransport::emit(const std::string& /*event*/, const std::string& /*data*/) {
    // No-op for HTTP transport
    // Events are only supported in Socket.IO mode
}

// ============================================================================
// CONFIGURATION
// ============================================================================

void HTTPTransport::set_timeout(int seconds) {
    timeout_seconds_ = seconds;
    if (http_client_) {
        http_client_->set_timeout(seconds);
    }
}

std::string HTTPTransport::get_session_id() const {
    return session_id_;
}

void HTTPTransport::set_session_id(const std::string& session_id) {
    session_id_ = session_id;
}

std::string HTTPTransport::get_server_url() const {
    return server_url_;
}

std::string HTTPTransport::get_last_error() const {
    return last_error_;
}

// ============================================================================
// HTTP-SPECIFIC METHODS
// ============================================================================

void HTTPTransport::set_ssl_verify(bool verify) {
    if (http_client_) {
        http_client_->set_ssl_verify(verify);
    }
}

void HTTPTransport::set_ssl_fingerprint(const std::string& fingerprint) {
    expected_ssl_fingerprint_ = fingerprint;
    if (http_client_) {
        http_client_->set_ssl_fingerprint(fingerprint);
    }
}

std::string HTTPTransport::get_server_fingerprint() {
    if (http_client_) {
        return http_client_->get_server_fingerprint();
    }
    return "";
}

bool HTTPTransport::verify_ssl_fingerprint(const std::string& expected_fingerprint) {
    if (http_client_) {
        return http_client_->verify_ssl_fingerprint(expected_fingerprint);
    }
    return true;  // No client, nothing to verify
}

http::Client* HTTPTransport::get_http_client() {
    return http_client_.get();
}

// ============================================================================
// FACTORY FUNCTION
// ============================================================================

std::unique_ptr<Transport> create_transport(
    const std::string& server_url,
    bool use_socket
) {
    if (use_socket) {
        return std::make_unique<SocketIOTransport>(server_url);
    }

    return std::make_unique<HTTPTransport>(server_url);
}

} // namespace transport
} // namespace oliviauth
