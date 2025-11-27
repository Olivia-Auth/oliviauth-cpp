#pragma once

/**
 * @file socketio_transport.h
 * @brief Socket.IO transport implementation using IXWebSocket
 *
 * Implements the Engine.IO/Socket.IO protocol over WebSocket for real-time
 * communication with the OliviaAuth server.
 */

#include "transport.h"
#include "../../deps/ixwebsocket/IXWebSocket.h"
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <map>
#include <thread>
#include <queue>

namespace oliviauth {
namespace transport {

/**
 * @brief Socket.IO-based transport implementation
 *
 * Implements Socket.IO protocol over WebSocket using IXWebSocket library.
 * Supports real-time events, automatic reconnection, and heartbeat.
 *
 * Engine.IO Packet Types:
 * - 0 = open (handshake)
 * - 1 = close
 * - 2 = ping
 * - 3 = pong
 * - 4 = message (contains Socket.IO packet)
 *
 * Socket.IO Packet Types (inside Engine.IO message):
 * - 0 = connect
 * - 1 = disconnect
 * - 2 = event (["event_name", data])
 * - 3 = ack
 * - 4 = error
 */
class SocketIOTransport : public Transport {
public:
    /**
     * @brief Construct Socket.IO transport
     * @param server_url Server URL (e.g., "https://api.oliviauth.xyz")
     */
    explicit SocketIOTransport(const std::string& server_url);

    ~SocketIOTransport() override;

    // Non-copyable
    SocketIOTransport(const SocketIOTransport&) = delete;
    SocketIOTransport& operator=(const SocketIOTransport&) = delete;

    // ========================================================================
    // CONNECTION LIFECYCLE
    // ========================================================================

    bool connect() override;
    void disconnect() override;
    bool is_connected() const override;

    /**
     * @brief Re-authenticate WebSocket connection with session_id
     *
     * Call this after session_id is set to join the Socket.IO room
     * and receive real-time events (like session_expired).
     */
    void reauthenticate();

    // ========================================================================
    // REQUEST/RESPONSE
    // ========================================================================

    /**
     * @brief Send request and wait for response (request-response pattern)
     *
     * Emits 'api_request' event and waits for corresponding 'api_response'.
     * Uses request_id for correlation.
     */
    Response send_request(
        const std::string& endpoint,
        const std::string& body,
        const std::map<std::string, std::string>& headers = {},
        int timeout_ms = 30000
    ) override;

    // ========================================================================
    // EVENT SYSTEM
    // ========================================================================

    /**
     * @brief Register handler for a specific event
     * @param event Event name (e.g., "session_expired", "server_command")
     * @param callback Function to call when event received
     */
    void on_event(const std::string& event, EventCallback callback) override;

    /**
     * @brief Emit an event to server
     * @param event Event name
     * @param data Event data (JSON string)
     */
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
    // SOCKET.IO-SPECIFIC METHODS
    // ========================================================================

    /**
     * @brief Set SSL verification
     * @param verify Enable/disable verification
     */
    void set_ssl_verify(bool verify);

    /**
     * @brief Set expected SSL fingerprint (SHA256) for certificate pinning
     * @param fingerprint Hex-encoded SHA256 fingerprint
     */
    void set_ssl_fingerprint(const std::string& fingerprint);

    /**
     * @brief Verify SSL certificate fingerprint before connecting
     * @param expected_fingerprint Expected SHA256 fingerprint
     * @return true if matches, throws on mismatch
     */
    bool verify_ssl_fingerprint(const std::string& expected_fingerprint);

    /**
     * @brief Set reconnection options
     * @param enabled Enable automatic reconnection
     * @param max_attempts Maximum reconnection attempts (0 = infinite)
     * @param delay_ms Initial delay between attempts in milliseconds
     */
    void set_reconnection(bool enabled, int max_attempts = 5, int delay_ms = 1000);

    /**
     * @brief Check if Socket.IO handshake is complete
     */
    bool is_socket_io_connected() const;

    /**
     * @brief Get the Engine.IO session ID
     */
    std::string get_engine_io_sid() const;

    /**
     * @brief Start preventive refresh timer (public for reconnect logic)
     * Refreshes connection every 50s to avoid Cloudflare 100s timeout
     */
    void start_refresh_timer();

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    /**
     * @brief Do HTTP polling handshake to get Engine.IO session ID
     * @return Session ID (sid) or empty string on failure
     */
    std::string do_polling_handshake();

    /**
     * @brief Build WebSocket URL from HTTP URL
     * Converts https://host to wss://host/socket.io/?EIO=4&transport=websocket
     */
    std::string build_websocket_url() const;

    /**
     * @brief Handle incoming WebSocket message
     */
    void handle_message(const std::string& message);

    /**
     * @brief Handle Engine.IO packet
     */
    void handle_engine_io_packet(char type, const std::string& data);

    /**
     * @brief Handle Socket.IO packet
     */
    void handle_socket_io_packet(char type, const std::string& data);

    /**
     * @brief Parse Engine.IO open packet
     */
    void parse_engine_io_open(const std::string& data);

    /**
     * @brief Send Engine.IO packet
     */
    void send_engine_io_packet(char type, const std::string& data = "");

    /**
     * @brief Send Socket.IO event
     */
    void send_socket_io_event(const std::string& event, const std::string& data);

    /**
     * @brief Send Socket.IO connect packet
     */
    void send_socket_io_connect();

    /**
     * @brief Generate unique request ID
     */
    std::string generate_request_id();

    /**
     * @brief Start heartbeat thread
     */
    void start_heartbeat();

    /**
     * @brief Stop heartbeat thread
     */
    void stop_heartbeat();

    /**
     * @brief Heartbeat worker function
     */
    void heartbeat_worker();

    /**
     * @brief Stop refresh timer
     */
    void stop_refresh_timer();

    /**
     * @brief Refresh timer worker function
     */
    void refresh_timer_worker();

    /**
     * @brief Perform preventive refresh
     * Disconnects, recreates WebSocket, reconnects, and re-authenticates
     */
    void do_refresh();

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    std::string server_url_;
    std::string session_id_;
    std::string last_error_;

    // WebSocket
    ix::WebSocket websocket_;
    std::atomic<bool> connected_{false};
    std::atomic<bool> socket_io_connected_{false};

    // Engine.IO state
    std::string engine_io_sid_;
    int ping_interval_ms_ = 25000;
    int ping_timeout_ms_ = 20000;

    // Event handlers
    std::mutex handlers_mutex_;
    std::map<std::string, EventCallback> event_handlers_;

    // Request-Response correlation
    std::mutex requests_mutex_;
    std::condition_variable requests_cv_;
    std::map<std::string, std::string> pending_responses_;
    std::map<std::string, bool> response_received_;

    // Heartbeat
    std::atomic<bool> heartbeat_running_{false};
    std::thread heartbeat_thread_;
    std::mutex heartbeat_mutex_;
    std::condition_variable heartbeat_cv_;

    // Preventive Refresh (Cloudflare 100s timeout workaround)
    std::atomic<bool> refresh_timer_running_{false};
    std::atomic<bool> refresh_in_progress_{false};
    std::thread refresh_timer_thread_;
    std::mutex refresh_mutex_;
    std::condition_variable refresh_cv_;
    int refresh_interval_seconds_ = 50;  // Refresh before Cloudflare 100s timeout

    // Configuration
    int timeout_seconds_ = 30;
    bool ssl_verify_ = true;
    std::string ssl_fingerprint_;  // Expected SSL certificate SHA256 fingerprint
    bool reconnection_enabled_ = true;
    int reconnection_attempts_ = 5;
    int reconnection_delay_ms_ = 1000;

    // Request ID counter
    std::atomic<uint64_t> request_counter_{0};
};

} // namespace transport
} // namespace oliviauth
