#pragma once

/**
 * @file transport.h
 * @brief Abstract transport interface for HTTP and Socket.IO communication
 *
 * This abstraction allows OliviaAuth to work with both HTTP and Socket.IO
 * transports seamlessly.
 */

#include <string>
#include <map>
#include <functional>
#include <memory>

namespace oliviauth {
namespace transport {

/**
 * @brief Response structure from transport layer
 */
struct Response {
    bool success = false;
    int status_code = 0;
    std::string body;
    std::string error;

    bool ok() const { return success && status_code >= 200 && status_code < 300; }
};

/**
 * @brief Abstract base class for transport implementations
 *
 * Both HTTP and Socket.IO transports implement this interface,
 * allowing OliviaAuth to switch between them transparently.
 */
class Transport {
public:
    virtual ~Transport() = default;

    // ========================================================================
    // CONNECTION LIFECYCLE
    // ========================================================================

    /**
     * @brief Establish connection to server
     * @return true if connection successful
     */
    virtual bool connect() = 0;

    /**
     * @brief Disconnect from server
     */
    virtual void disconnect() = 0;

    /**
     * @brief Check if currently connected
     * @return true if connected
     */
    virtual bool is_connected() const = 0;

    // ========================================================================
    // REQUEST/RESPONSE (HTTP-STYLE)
    // ========================================================================

    /**
     * @brief Send a request and wait for response
     *
     * For HTTP: Makes a POST request to /api/1.0/{endpoint}
     * For Socket.IO: Emits 'api_request' event and waits for 'api_response'
     *
     * @param endpoint API endpoint (e.g., "session", "init", "license")
     * @param body Request body (JSON string)
     * @param headers Additional headers (mainly for Session-ID)
     * @param timeout_ms Timeout in milliseconds
     * @return Response with status and body
     */
    virtual Response send_request(
        const std::string& endpoint,
        const std::string& body,
        const std::map<std::string, std::string>& headers = {},
        int timeout_ms = 30000
    ) = 0;

    // ========================================================================
    // EVENT SYSTEM (SOCKET.IO ONLY - NO-OP FOR HTTP)
    // ========================================================================

    /**
     * @brief Callback type for event handlers
     */
    using EventCallback = std::function<void(const std::string& data)>;

    /**
     * @brief Register handler for a specific event
     *
     * For Socket.IO: Registers event listener
     * For HTTP: No-op (events not supported)
     *
     * @param event Event name (e.g., "session_expired", "server_command")
     * @param callback Function to call when event received
     */
    virtual void on_event(const std::string& event, EventCallback callback) = 0;

    /**
     * @brief Emit an event to server
     *
     * For Socket.IO: Emits event via WebSocket
     * For HTTP: No-op (or could make POST request)
     *
     * @param event Event name
     * @param data Event data (JSON string)
     */
    virtual void emit(const std::string& event, const std::string& data) = 0;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    /**
     * @brief Set request timeout
     * @param seconds Timeout in seconds
     */
    virtual void set_timeout(int seconds) = 0;

    /**
     * @brief Get the session ID (if set)
     * @return Session ID string
     */
    virtual std::string get_session_id() const = 0;

    /**
     * @brief Set the session ID for requests
     * @param session_id Session ID to use
     */
    virtual void set_session_id(const std::string& session_id) = 0;

    /**
     * @brief Get the server URL
     * @return Server URL string
     */
    virtual std::string get_server_url() const = 0;

    /**
     * @brief Get last error message
     * @return Error string
     */
    virtual std::string get_last_error() const = 0;
};

/**
 * @brief Factory function to create appropriate transport
 *
 * @param server_url Server URL
 * @param use_socket true for Socket.IO, false for HTTP
 * @return Unique pointer to Transport implementation
 */
std::unique_ptr<Transport> create_transport(
    const std::string& server_url,
    bool use_socket = false
);

} // namespace transport
} // namespace oliviauth
