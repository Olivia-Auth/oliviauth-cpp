/**
 * @file http.cpp
 * @brief HTTP client implementation using cpp-httplib
 */

#include "http.h"

// Enable OpenSSL support for HTTPS
#define CPPHTTPLIB_OPENSSL_SUPPORT

#ifdef OLIVIAUTH_USE_EXTERNAL_HTTPLIB
    #include <httplib.h>
#else
    #include "../deps/httplib.h"
#endif

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

#include <regex>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <iostream>

namespace oliviauth {
namespace http {

// ============================================================================
// IMPLEMENTATION
// ============================================================================

struct Client::Impl {
    std::string base_url;
    std::string host;
    int port = 443;
    bool use_ssl = true;

    std::unique_ptr<httplib::Client> client;

    int timeout_seconds = 30;
    bool ssl_verify = true;
    std::string expected_fingerprint;
    std::map<std::string, std::string> default_headers;

    std::string last_error;

    void parse_url() {
        std::regex url_regex(R"(^(https?):\/\/([^:\/]+)(?::(\d+))?(\/.*)?$)");
        std::smatch match;

        if (std::regex_match(base_url, match, url_regex)) {
            use_ssl = (match[1].str() == "https");
            host = match[2].str();
            if (match[3].matched) {
                port = std::stoi(match[3].str());
            } else {
                port = use_ssl ? 443 : 80;
            }
        }
    }

    void setup_client() {
        // Build scheme://host:port format without trailing slash
        // cpp-httplib expects clean URL format
        std::string scheme = use_ssl ? "https" : "http";
        std::string url = scheme + "://" + host + ":" + std::to_string(port);

        client = std::make_unique<httplib::Client>(url.c_str());

        // Set timeouts
        client->set_connection_timeout(timeout_seconds, 0);
        client->set_read_timeout(timeout_seconds, 0);
        client->set_write_timeout(timeout_seconds, 0);

        // SSL settings
        if (use_ssl) {
            if (ssl_verify) {
                client->enable_server_certificate_verification(true);
            } else {
                client->enable_server_certificate_verification(false);
            }
        }

        // Set default headers
        client->set_default_headers({
            {"Content-Type", "application/json"},
            {"Accept", "application/json"}
        });
    }

    std::string calculate_cert_fingerprint(X509* cert) {
        unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
        unsigned int len = SHA256_DIGEST_LENGTH;

        X509_digest(cert, EVP_sha256(), sha256_hash, &len);

        std::stringstream ss;
        for (unsigned int i = 0; i < len; i++) {
            ss << std::hex << std::setfill('0') << std::setw(2)
               << (int)sha256_hash[i];
        }

        return ss.str();
    }
};

// ============================================================================
// PUBLIC METHODS
// ============================================================================

Client::Client(const std::string& base_url)
    : impl_(std::make_unique<Impl>())
{
    impl_->base_url = base_url;
    impl_->parse_url();
    impl_->setup_client();
}

Client::~Client() = default;

void Client::set_timeout(int seconds) {
    impl_->timeout_seconds = seconds;
    if (impl_->client) {
        impl_->client->set_connection_timeout(seconds, 0);
        impl_->client->set_read_timeout(seconds, 0);
        impl_->client->set_write_timeout(seconds, 0);
    }
}

void Client::set_ssl_verify(bool verify) {
    impl_->ssl_verify = verify;
    if (impl_->client && impl_->use_ssl) {
        impl_->client->enable_server_certificate_verification(verify);
    }
}

void Client::set_ssl_fingerprint(const std::string& fingerprint) {
    impl_->expected_fingerprint = fingerprint;
}

void Client::set_header(const std::string& name, const std::string& value) {
    impl_->default_headers[name] = value;
}

void Client::remove_header(const std::string& name) {
    impl_->default_headers.erase(name);
}

Response Client::post(
    const std::string& endpoint,
    const std::string& json_body,
    const std::map<std::string, std::string>& extra_headers
) {
    Response response;

    if (!impl_->client) {
        response.error = "Client not initialized";
        impl_->last_error = response.error;
        return response;
    }

    // Combine headers
    httplib::Headers headers;
    for (const auto& [name, value] : impl_->default_headers) {
        headers.insert({name, value});
    }
    for (const auto& [name, value] : extra_headers) {
        headers.insert({name, value});
    }

    // Make request
    auto result = impl_->client->Post(
        endpoint.c_str(),
        headers,
        json_body,
        "application/json"
    );

    if (result) {
        response.status_code = result->status;
        response.body = result->body;

        for (const auto& [name, value] : result->headers) {
            response.headers[name] = value;
        }
    } else {
        response.error = "Request failed: " + httplib::to_string(result.error());
        impl_->last_error = response.error;
    }

    return response;
}

Response Client::get(
    const std::string& endpoint,
    const std::map<std::string, std::string>& extra_headers
) {
    Response response;

    if (!impl_->client) {
        response.error = "Client not initialized";
        impl_->last_error = response.error;
        return response;
    }

    // Combine headers
    httplib::Headers headers;
    for (const auto& [name, value] : impl_->default_headers) {
        headers.insert({name, value});
    }
    for (const auto& [name, value] : extra_headers) {
        headers.insert({name, value});
    }

    // Make request
    auto result = impl_->client->Get(endpoint.c_str(), headers);

    if (result) {
        response.status_code = result->status;
        response.body = result->body;

        for (const auto& [name, value] : result->headers) {
            response.headers[name] = value;
        }
    } else {
        response.error = "Request failed: " + httplib::to_string(result.error());
        impl_->last_error = response.error;
    }

    return response;
}

std::string Client::get_server_fingerprint() {
    if (!impl_->use_ssl) {
        return "";
    }

    // Create a temporary SSL connection to get the certificate
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        return "";
    }

    // Disable certificate verification for fingerprint retrieval
    // We're manually verifying via fingerprint, so we don't need CA chain verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    BIO* bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        SSL_CTX_free(ctx);
        return "";
    }

    // Set hostname for connection
    std::string connect_str = impl_->host + ":" + std::to_string(impl_->port);
    BIO_set_conn_hostname(bio, connect_str.c_str());

    // Get SSL object from BIO and set SNI hostname
    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);

    if (ssl) {
        SSL_set_tlsext_host_name(ssl, impl_->host.c_str());
    }

    // Attempt connection
    if (BIO_do_connect(bio) <= 0) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return "";
    }

    // Perform SSL handshake
    if (BIO_do_handshake(bio) <= 0) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return "";
    }

    // Get certificate from SSL connection
    if (!ssl) {
        BIO_get_ssl(bio, &ssl);
    }

    if (!ssl) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return "";
    }

    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return "";
    }

    std::string fingerprint = impl_->calculate_cert_fingerprint(cert);

    X509_free(cert);
    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return fingerprint;
}

bool Client::verify_ssl_fingerprint(const std::string& expected_fingerprint) {
    // Skip verification if no fingerprint provided
    if (expected_fingerprint.empty()) {
        return true;
    }

    // Only verify for HTTPS
    if (!impl_->use_ssl) {
        return true;
    }

    // Get actual server fingerprint
    std::string actual = get_server_fingerprint();
    if (actual.empty()) {
        impl_->last_error = "Failed to retrieve server SSL certificate fingerprint";
        throw std::runtime_error(impl_->last_error);
    }

    // Convert both to lowercase for comparison
    std::string expected_lower = expected_fingerprint;
    std::string actual_lower = actual;
    std::transform(expected_lower.begin(), expected_lower.end(), expected_lower.begin(), ::tolower);
    std::transform(actual_lower.begin(), actual_lower.end(), actual_lower.begin(), ::tolower);

    if (expected_lower != actual_lower) {
        impl_->last_error = "SSL certificate fingerprint mismatch!\nExpected: " + expected_fingerprint + "\nGot:      " + actual;
        throw std::runtime_error(impl_->last_error);
    }

    return true;
}

const std::string& Client::last_error() const {
    return impl_->last_error;
}

} // namespace http
} // namespace oliviauth
