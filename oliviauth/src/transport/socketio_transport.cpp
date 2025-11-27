/**
 * @file socketio_transport.cpp
 * @brief Socket.IO transport implementation using IXWebSocket
 */

#include "socketio_transport.h"
#include "../http.h"  // For SSL fingerprint verification
#include "../xor.h"
#include "../../deps/json.hpp"
#include "../../deps/ixwebsocket/IXHttpClient.h"
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <random>
#include <algorithm>
#include <iostream>

// Debug logging (if enabled in oliviauth.cpp)
namespace oliviauth {
    extern std::atomic<bool> g_debug_mode;
}
#define SIO_DEBUG(msg) do { if (oliviauth::g_debug_mode) { std::cerr << "[SOCKET.IO] " << msg << std::endl; } } while(0)

namespace oliviauth {
namespace transport {

using json = nlohmann::json;

// Engine.IO packet types
constexpr char EIO_OPEN = '0';
constexpr char EIO_CLOSE = '1';
constexpr char EIO_PING = '2';
constexpr char EIO_PONG = '3';
constexpr char EIO_MESSAGE = '4';

// Socket.IO packet types
constexpr char SIO_CONNECT = '0';
constexpr char SIO_DISCONNECT = '1';
constexpr char SIO_EVENT = '2';
constexpr char SIO_ACK = '3';
constexpr char SIO_ERROR = '4';

SocketIOTransport::SocketIOTransport(const std::string& server_url)
    : server_url_(server_url)
{
    // Register handler for 'connected' event from server
    on_event(RXor("connected"), [this](const std::string& data) {
        try {
            auto j = json::parse(data);
            SIO_DEBUG("Received 'connected' event: " << data);

            if (j.contains(RXor("requires_auth")) && j[RXor("requires_auth")].get<bool>()) {
                SIO_DEBUG("Server requires authentication via 'authenticate' event");

                // Send authenticate event if we have session_id
                if (!session_id_.empty()) {
                    SIO_DEBUG("Sending 'authenticate' event with session_id: " << session_id_.substr(0, 8) << "...");
                    json auth_data = {{RXor("session_id"), session_id_}};
                    send_socket_io_event(RXor("authenticate"), auth_data.dump());
                }
            }

            if (j.contains(RXor("room_id"))) {
                SIO_DEBUG("Server confirmed room: " << j[RXor("room_id")].get<std::string>());
            }
        } catch (const std::exception& e) {
            SIO_DEBUG("Failed to parse 'connected' event: " << e.what());
        }
    });
}

SocketIOTransport::~SocketIOTransport() {
    stop_refresh_timer();
    disconnect();
}

// ============================================================================
// CONNECTION LIFECYCLE
// ============================================================================

bool SocketIOTransport::connect() {
    if (connected_) {
        return true;
    }

    SIO_DEBUG("Connecting to " << server_url_);

    // Connect directly via WebSocket (like Python SDK with transports=['websocket'])
    // Do NOT do polling handshake first - flask-socketio expects direct websocket connection
    engine_io_sid_.clear();

    // Build WebSocket URL (without sid for direct connection)
    std::string ws_url = build_websocket_url();
    SIO_DEBUG("WebSocket URL: " << ws_url);

    websocket_.setUrl(ws_url);

    // Set extra headers for Socket.IO compatibility
    ix::WebSocketHttpHeaders headers;
    headers["User-Agent"] = "oliviauth-cpp/1.0";
    headers["Origin"] = "https://oliviauth.xyz";  // Use allowed CORS origin
    websocket_.setExtraHeaders(headers);

    // Configure TLS only for wss://
    if (ws_url.substr(0, 4) == "wss:") {
        ix::SocketTLSOptions tls_options;
        tls_options.tls = true;
        if (!ssl_verify_) {
            tls_options.caFile = "NONE";
        }
        websocket_.setTLSOptions(tls_options);
    }

    // Configure reconnection
    if (reconnection_enabled_) {
        websocket_.enableAutomaticReconnection();
        websocket_.setMinWaitBetweenReconnectionRetries(reconnection_delay_ms_);
        websocket_.setMaxWaitBetweenReconnectionRetries(reconnection_delay_ms_ * 4);
    } else {
        websocket_.disableAutomaticReconnection();
    }

    // Set message callback
    websocket_.setOnMessageCallback([this](const ix::WebSocketMessagePtr& msg) {
        switch (msg->type) {
            case ix::WebSocketMessageType::Open: {
                SIO_DEBUG("WebSocket connected");

                // Check if this is a reconnection
                bool is_reconnection = !engine_io_sid_.empty() || !session_id_.empty();
                if (is_reconnection) {
                    SIO_DEBUG("⚠ WebSocket RECONNECTED (was disconnected, now back)");
                }

                connected_ = true;

                // If we upgraded with sid from polling, we need to send probe and upgrade
                if (!engine_io_sid_.empty()) {
                    SIO_DEBUG("Sending upgrade probe");
                    websocket_.send("2probe");  // Engine.IO ping probe
                }
                break;
            }

            case ix::WebSocketMessageType::Close:
                SIO_DEBUG("⚠ WebSocket CLOSED: " << msg->closeInfo.reason << " (code: " << msg->closeInfo.code << ")");
                if (socket_io_connected_) {
                    SIO_DEBUG("⚠ Lost Socket.IO room connection - will rejoin on reconnect");
                }
                connected_ = false;
                socket_io_connected_ = false;
                stop_heartbeat();
                // Notify waiting requests
                requests_cv_.notify_all();
                break;

            case ix::WebSocketMessageType::Error:
                SIO_DEBUG("WebSocket error: " << msg->errorInfo.reason);
                last_error_ = msg->errorInfo.reason;
                connected_ = false;
                socket_io_connected_ = false;
                requests_cv_.notify_all();
                break;

            case ix::WebSocketMessageType::Message:
                handle_message(msg->str);
                break;

            default:
                break;
        }
    });

    // Start connection
    websocket_.start();

    // Wait for Engine.IO open packet
    auto start = std::chrono::steady_clock::now();
    while (!socket_io_connected_) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
        if (elapsed >= timeout_seconds_) {
            SIO_DEBUG("Connection timeout");
            last_error_ = "Connection timeout";
            websocket_.stop();
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    SIO_DEBUG("Socket.IO connected, sid=" << engine_io_sid_);
    return true;
}

void SocketIOTransport::disconnect() {
    SIO_DEBUG("Disconnecting");

    stop_refresh_timer();  // Stop preventive refresh first
    stop_heartbeat();

    if (connected_) {
        // Send Socket.IO disconnect
        send_engine_io_packet(EIO_MESSAGE, std::string(1, SIO_DISCONNECT));
        websocket_.stop();
    }

    connected_ = false;
    socket_io_connected_ = false;
    engine_io_sid_.clear();

    // Clear pending requests
    {
        std::lock_guard<std::mutex> lock(requests_mutex_);
        pending_responses_.clear();
        response_received_.clear();
    }
    requests_cv_.notify_all();
}

void SocketIOTransport::reauthenticate() {
    // For initial authentication, just check WebSocket connection
    // socket_io_connected_ might not be true yet on first call
    if (!connected_ || session_id_.empty()) {
        return;
    }

    // Send Socket.IO disconnect first
    send_engine_io_packet(EIO_MESSAGE, std::string(1, SIO_DISCONNECT));

    // Wait for server to process disconnect
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Send Socket.IO connect
    send_socket_io_connect();

    // Wait for CONNECT ACK to be received
    // The CONNECT ACK handler (handle_socket_io_packet) will automatically
    // send the 'authenticate' event when it sees we have a session_id
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

bool SocketIOTransport::is_connected() const {
    return connected_ && socket_io_connected_;
}

// ============================================================================
// REQUEST/RESPONSE
// ============================================================================

Response SocketIOTransport::send_request(
    const std::string& endpoint,
    const std::string& body,
    const std::map<std::string, std::string>& headers,
    int timeout_ms
) {
    Response response;

    if (!is_connected()) {
        response.success = false;
        response.error = "Not connected";
        last_error_ = response.error;
        return response;
    }

    // Generate unique request ID
    std::string request_id = generate_request_id();

    // Build request payload
    json payload;
    payload[RXor("endpoint")] = endpoint;
    payload[RXor("request_id")] = request_id;

    // Parse body as JSON if possible
    try {
        payload[RXor("data")] = json::parse(body);
    } catch (...) {
        payload[RXor("data")] = body;
    }

    // Add session ID to payload if set
    if (!session_id_.empty()) {
        payload[RXor("session_id")] = session_id_;
    }

    // Add any custom headers
    if (!headers.empty()) {
        json hdrs;
        for (const auto& [key, value] : headers) {
            hdrs[key] = value;
        }
        payload[RXor("headers")] = hdrs;
    }

    SIO_DEBUG("Sending request: endpoint=" << endpoint << ", request_id=" << request_id);

    // Register for response
    {
        std::lock_guard<std::mutex> lock(requests_mutex_);
        response_received_[request_id] = false;
    }

    // Emit the request
    send_socket_io_event(RXor("api_request"), payload.dump());

    // Wait for response
    {
        std::unique_lock<std::mutex> lock(requests_mutex_);
        bool received = requests_cv_.wait_for(
            lock,
            std::chrono::milliseconds(timeout_ms),
            [this, &request_id]() {
                return response_received_.count(request_id) && response_received_[request_id];
            }
        );

        if (received && pending_responses_.count(request_id)) {
            response.success = true;
            response.status_code = 200;
            response.body = pending_responses_[request_id];
            pending_responses_.erase(request_id);
            response_received_.erase(request_id);
            SIO_DEBUG("Received response for " << request_id);
        } else {
            response.success = false;
            response.error = "Request timeout";
            last_error_ = response.error;
            response_received_.erase(request_id);
            SIO_DEBUG("Request timeout for " << request_id);
        }
    }

    return response;
}

// ============================================================================
// EVENT SYSTEM
// ============================================================================

void SocketIOTransport::on_event(const std::string& event, EventCallback callback) {
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    event_handlers_[event] = callback;
    SIO_DEBUG("Registered handler for event: " << event);
}

void SocketIOTransport::emit(const std::string& event, const std::string& data) {
    if (!is_connected()) {
        SIO_DEBUG("Cannot emit event, not connected");
        return;
    }

    send_socket_io_event(event, data);
}

// ============================================================================
// CONFIGURATION
// ============================================================================

void SocketIOTransport::set_timeout(int seconds) {
    timeout_seconds_ = seconds;
}

std::string SocketIOTransport::get_session_id() const {
    return session_id_;
}

void SocketIOTransport::set_session_id(const std::string& session_id) {
    session_id_ = session_id;
}

std::string SocketIOTransport::get_server_url() const {
    return server_url_;
}

std::string SocketIOTransport::get_last_error() const {
    return last_error_;
}

void SocketIOTransport::set_ssl_verify(bool verify) {
    ssl_verify_ = verify;
}

void SocketIOTransport::set_ssl_fingerprint(const std::string& fingerprint) {
    ssl_fingerprint_ = fingerprint;
}

bool SocketIOTransport::verify_ssl_fingerprint(const std::string& expected_fingerprint) {
    SIO_DEBUG(">>> verify_ssl_fingerprint() called");

    if (expected_fingerprint.empty()) {
        SIO_DEBUG("No SSL fingerprint to verify, skipping");
        return true;
    }

    SIO_DEBUG("Verifying SSL fingerprint...");

    // Use HTTP client to get SSL certificate fingerprint
    // This verifies the server certificate BEFORE establishing WebSocket
    SIO_DEBUG("Creating HTTP client for SSL verification...");
    http::Client http_client(server_url_);
    SIO_DEBUG("HTTP client created, setting timeout...");
    http_client.set_timeout(10);
    SIO_DEBUG("Timeout set, getting server fingerprint...");

    std::string actual = http_client.get_server_fingerprint();
    SIO_DEBUG("Got fingerprint: " << (actual.empty() ? "EMPTY!" : actual.substr(0, 16) + "..."));

    SIO_DEBUG("Exiting scope - http_client will destruct now...");
    // http_client will destruct here - this might be where the crash happens

    if (actual.empty()) {
        last_error_ = "Failed to retrieve server SSL certificate fingerprint";
        throw std::runtime_error(last_error_);
    }

    SIO_DEBUG("Converting fingerprints to lowercase...");
    // Convert both to lowercase for comparison
    std::string expected_lower = expected_fingerprint;
    std::string actual_lower = actual;
    std::transform(expected_lower.begin(), expected_lower.end(), expected_lower.begin(), ::tolower);
    std::transform(actual_lower.begin(), actual_lower.end(), actual_lower.begin(), ::tolower);

    SIO_DEBUG("Comparing fingerprints...");
    if (expected_lower != actual_lower) {
        last_error_ = "SSL certificate fingerprint mismatch! Expected: " + expected_fingerprint + ", Got: " + actual;
        throw std::runtime_error("SSL certificate verification failed - fingerprint mismatch");
    }

    SIO_DEBUG("SSL certificate fingerprint verified successfully");
    SIO_DEBUG("<<< verify_ssl_fingerprint() returning true");
    return true;
}

void SocketIOTransport::set_reconnection(bool enabled, int max_attempts, int delay_ms) {
    reconnection_enabled_ = enabled;
    reconnection_attempts_ = max_attempts;
    reconnection_delay_ms_ = delay_ms;
}

bool SocketIOTransport::is_socket_io_connected() const {
    return socket_io_connected_;
}

std::string SocketIOTransport::get_engine_io_sid() const {
    return engine_io_sid_;
}

// ============================================================================
// INTERNAL METHODS
// ============================================================================

std::string SocketIOTransport::do_polling_handshake() {
    // Do HTTP GET to /socket.io/?EIO=4&transport=polling to get the sid
    SIO_DEBUG("Doing polling handshake...");

    ix::HttpClient httpClient;
    ix::HttpRequestArgsPtr args = httpClient.createRequest();

    // Build polling URL
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();

    std::ostringstream url_oss;
    url_oss << server_url_ << "/socket.io/?EIO=4&transport=polling&t=" << ms;

    args->url = url_oss.str();
    args->extraHeaders["User-Agent"] = "oliviauth-cpp/1.0";
    args->extraHeaders["Origin"] = "https://oliviauth.xyz";  // Use allowed CORS origin

    SIO_DEBUG("Polling URL: " << args->url);

    auto response = httpClient.get(args->url, args);

    if (response->statusCode != 200) {
        SIO_DEBUG("Polling failed with status: " << response->statusCode);
        return "";
    }

    // Response format: "0{...json...}" where 0 is Engine.IO OPEN packet
    std::string body = response->body;
    SIO_DEBUG("Polling response: " << body.substr(0, 100));

    if (body.empty() || body[0] != '0') {
        SIO_DEBUG("Invalid polling response format");
        return "";
    }

    // Parse JSON from position 1
    try {
        auto j = json::parse(body.substr(1));
        if (j.contains("sid")) {
            std::string sid = j["sid"].get<std::string>();
            if (j.contains("pingInterval")) {
                ping_interval_ms_ = j["pingInterval"].get<int>();
            }
            if (j.contains("pingTimeout")) {
                ping_timeout_ms_ = j["pingTimeout"].get<int>();
            }
            return sid;
        }
    } catch (const std::exception& e) {
        SIO_DEBUG("Failed to parse polling response: " << e.what());
    }

    return "";
}

std::string SocketIOTransport::build_websocket_url() const {
    std::string url = server_url_;

    // Convert http(s) to ws(s)
    if (url.substr(0, 8) == "https://") {
        url = "wss://" + url.substr(8);
    } else if (url.substr(0, 7) == "http://") {
        url = "ws://" + url.substr(7);
    }

    // Remove trailing slash
    if (!url.empty() && url.back() == '/') {
        url.pop_back();
    }

    // Add Socket.IO path and Engine.IO parameters
    // EIO=4 is Engine.IO protocol version 4 (Socket.IO v4)
    // t= is a cache-busting timestamp parameter
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();

    std::ostringstream oss;
    oss << url << "/socket.io/?EIO=4&transport=websocket&t=" << ms;

    // Add sid if we have one from polling
    if (!engine_io_sid_.empty()) {
        oss << "&sid=" << engine_io_sid_;
    }

    return oss.str();
}

void SocketIOTransport::handle_message(const std::string& message) {
    if (message.empty()) {
        return;
    }

    SIO_DEBUG("Received raw: " << message.substr(0, 100) << (message.size() > 100 ? "..." : ""));

    // Handle special upgrade messages
    if (message == "3probe") {
        // Server confirmed probe, complete upgrade
        SIO_DEBUG("Received probe response, completing upgrade");
        websocket_.send("5");  // Engine.IO upgrade
        // Now send Socket.IO connect
        send_socket_io_connect();
        return;
    }

    // First character is Engine.IO packet type
    char eio_type = message[0];
    std::string data = message.length() > 1 ? message.substr(1) : "";

    handle_engine_io_packet(eio_type, data);
}

void SocketIOTransport::handle_engine_io_packet(char type, const std::string& data) {
    switch (type) {
        case EIO_OPEN:
            SIO_DEBUG("Engine.IO OPEN");
            // Only parse if we don't have sid from polling
            if (engine_io_sid_.empty()) {
                parse_engine_io_open(data);
            }
            // Send Socket.IO connect
            send_socket_io_connect();
            break;

        case EIO_CLOSE:
            SIO_DEBUG("Engine.IO CLOSE");
            connected_ = false;
            socket_io_connected_ = false;
            break;

        case EIO_PING:
            SIO_DEBUG("Engine.IO PING");
            send_engine_io_packet(EIO_PONG);
            break;

        case EIO_PONG:
            SIO_DEBUG("Engine.IO PONG");
            break;

        case EIO_MESSAGE:
            // Socket.IO packet inside
            if (!data.empty()) {
                char sio_type = data[0];
                std::string sio_data = data.length() > 1 ? data.substr(1) : "";
                handle_socket_io_packet(sio_type, sio_data);
            }
            break;
    }
}

void SocketIOTransport::handle_socket_io_packet(char type, const std::string& data) {
    switch (type) {
        case SIO_CONNECT:
            SIO_DEBUG("Socket.IO CONNECT");
            socket_io_connected_ = true;

            // Parse connect acknowledgment
            if (!data.empty()) {
                try {
                    auto j = json::parse(data);
                    if (j.contains("sid")) {
                        engine_io_sid_ = j["sid"].get<std::string>();
                        SIO_DEBUG("Socket.IO sid: " << engine_io_sid_);
                    }
                    if (j.contains("room_id")) {
                        SIO_DEBUG("Joined room: " << j["room_id"].get<std::string>());
                    }
                    if (j.contains("session_id")) {
                        SIO_DEBUG("Authenticated with session: " << j["session_id"].get<std::string>().substr(0, 8) << "...");
                    }
                } catch (const std::exception& e) {
                    SIO_DEBUG("Failed to parse CONNECT ack: " << e.what());
                }
            }

            // ALWAYS send authenticate event if we have a session_id
            // This handles both initial connection and reconnections (Cloudflare timeout)
            if (!session_id_.empty()) {
                json auth_data = {{RXor("session_id"), session_id_}};
                send_socket_io_event(RXor("authenticate"), auth_data.dump());
            }

            start_heartbeat();
            start_refresh_timer();  // Start preventive refresh (Cloudflare 100s timeout workaround)
            break;

        case SIO_DISCONNECT:
            SIO_DEBUG("⚠ Socket.IO DISCONNECT - lost connection to room!");
            socket_io_connected_ = false;
            stop_heartbeat();
            stop_refresh_timer();

            // If we have a session_id and this isn't a refresh, try to reconnect
            if (!session_id_.empty() && connected_ && !refresh_in_progress_) {
                SIO_DEBUG("Auto-reconnecting with session_id to rejoin room...");
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                send_socket_io_connect();
            }
            break;

        case SIO_EVENT:
            // Parse event: ["event_name", data]
            try {
                auto arr = json::parse(data);
                if (arr.is_array() && arr.size() >= 1) {
                    std::string event_name = arr[0].get<std::string>();
                    std::string event_data = arr.size() > 1 ? arr[1].dump() : "{}";

                    SIO_DEBUG("Socket.IO EVENT: " << event_name);

                    // Handle special events
                    if (event_name == RXor("api_response") || event_name == RXor("api_error")) {
                        // Request-response correlation
                        std::lock_guard<std::mutex> lock(requests_mutex_);

                        std::string req_id;

                        // Try to get request_id from response
                        try {
                            auto resp = json::parse(event_data);
                            if (resp.contains("request_id")) {
                                req_id = resp["request_id"].get<std::string>();
                            }
                        } catch (...) {}

                        // If no request_id in response, use the first pending request
                        // (server doesn't echo request_id, similar to Python SDK behavior)
                        if (req_id.empty() && !response_received_.empty()) {
                            // Find first request that hasn't received a response yet
                            for (const auto& [id, received] : response_received_) {
                                if (!received) {
                                    req_id = id;
                                    SIO_DEBUG("No request_id in response, using pending: " << req_id);
                                    break;
                                }
                            }
                        }

                        if (!req_id.empty()) {
                            pending_responses_[req_id] = event_data;
                            response_received_[req_id] = true;
                            requests_cv_.notify_all();
                            SIO_DEBUG("Response received for request: " << req_id);
                        } else {
                            SIO_DEBUG("Received " << event_name << " but no pending request to match");
                        }
                    }

                    // Call registered handler
                    {
                        std::lock_guard<std::mutex> lock(handlers_mutex_);
                        if (event_handlers_.count(event_name)) {
                            event_handlers_[event_name](event_data);
                        }
                    }
                }
            } catch (const std::exception& e) {
                SIO_DEBUG("Failed to parse event: " << e.what());
            }
            break;

        case SIO_ACK:
            SIO_DEBUG("Socket.IO ACK");
            break;

        case SIO_ERROR:
            SIO_DEBUG("Socket.IO ERROR: " << data);
            last_error_ = data;
            break;
    }
}

void SocketIOTransport::parse_engine_io_open(const std::string& data) {
    try {
        auto j = json::parse(data);
        if (j.contains("sid")) {
            engine_io_sid_ = j["sid"].get<std::string>();
        }
        if (j.contains("pingInterval")) {
            ping_interval_ms_ = j["pingInterval"].get<int>();
        }
        if (j.contains("pingTimeout")) {
            ping_timeout_ms_ = j["pingTimeout"].get<int>();
        }
        SIO_DEBUG("Engine.IO open: sid=" << engine_io_sid_
                  << ", pingInterval=" << ping_interval_ms_
                  << ", pingTimeout=" << ping_timeout_ms_);
    } catch (const std::exception& e) {
        SIO_DEBUG("Failed to parse open packet: " << e.what());
    }
}

void SocketIOTransport::send_engine_io_packet(char type, const std::string& data) {
    std::string packet(1, type);
    packet += data;
    websocket_.send(packet);
}

void SocketIOTransport::send_socket_io_event(const std::string& event, const std::string& data) {
    // Socket.IO event format: ["event_name", data]
    json arr = json::array();
    arr.push_back(event);

    // Try to parse data as JSON, otherwise use as string
    try {
        arr.push_back(json::parse(data));
    } catch (...) {
        arr.push_back(data);
    }

    // Wrap in Engine.IO message packet
    std::string packet;
    packet += EIO_MESSAGE;
    packet += SIO_EVENT;
    packet += arr.dump();

    SIO_DEBUG("Sending event: " << event);
    websocket_.send(packet);
}

void SocketIOTransport::send_socket_io_connect() {
    // Socket.IO connect packet: "40" for default namespace
    std::string packet;
    packet += EIO_MESSAGE;
    packet += SIO_CONNECT;
    packet += "{}";  // Always send empty auth in CONNECT packet

    websocket_.send(packet);
    SIO_DEBUG("Sending Socket.IO connect");

    // Note: Authentication will be sent automatically when we receive the CONNECT ack
    // See handle_socket_io_packet() SIO_CONNECT case
}

std::string SocketIOTransport::generate_request_id() {
    uint64_t counter = request_counter_++;
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();

    std::ostringstream oss;
    oss << std::hex << now << "-" << counter;
    return oss.str();
}

void SocketIOTransport::start_heartbeat() {
    if (heartbeat_running_) {
        return;
    }

    heartbeat_running_ = true;
    heartbeat_thread_ = std::thread(&SocketIOTransport::heartbeat_worker, this);
}

void SocketIOTransport::stop_heartbeat() {
    if (!heartbeat_running_) {
        return;
    }

    heartbeat_running_ = false;
    heartbeat_cv_.notify_all();

    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
}

void SocketIOTransport::heartbeat_worker() {
    SIO_DEBUG("Heartbeat worker started");

    while (heartbeat_running_ && is_connected()) {
        std::unique_lock<std::mutex> lock(heartbeat_mutex_);

        // Wait for ping interval or stop signal
        heartbeat_cv_.wait_for(
            lock,
            std::chrono::milliseconds(ping_interval_ms_),
            [this]() { return !heartbeat_running_; }
        );

        if (!heartbeat_running_ || !is_connected()) {
            break;
        }

        // Send Engine.IO ping
        SIO_DEBUG("Sending heartbeat ping");
        send_engine_io_packet(EIO_PING);
    }

    SIO_DEBUG("Heartbeat worker stopped");
}

// ============================================================================
// PREVENTIVE REFRESH (Cloudflare 100s timeout workaround)
// ============================================================================

void SocketIOTransport::start_refresh_timer() {
    if (refresh_timer_running_) {
        return;
    }

    SIO_DEBUG("Starting preventive refresh timer (" << refresh_interval_seconds_ << "s)");
    refresh_timer_running_ = true;
    refresh_timer_thread_ = std::thread(&SocketIOTransport::refresh_timer_worker, this);
}

void SocketIOTransport::stop_refresh_timer() {
    if (!refresh_timer_running_) {
        return;
    }

    SIO_DEBUG("Stopping refresh timer");
    refresh_timer_running_ = false;
    refresh_cv_.notify_all();

    if (refresh_timer_thread_.joinable()) {
        refresh_timer_thread_.join();
    }
}

void SocketIOTransport::refresh_timer_worker() {
    SIO_DEBUG("Refresh timer worker started");

    while (refresh_timer_running_ && is_connected()) {
        std::unique_lock<std::mutex> lock(refresh_mutex_);

        // Wait for refresh interval or stop signal
        bool stopped = refresh_cv_.wait_for(
            lock,
            std::chrono::seconds(refresh_interval_seconds_),
            [this]() { return !refresh_timer_running_; }
        );

        if (stopped || !refresh_timer_running_) {
            break;
        }

        // Skip if not connected or already refreshing
        if (!is_connected() || refresh_in_progress_) {
            continue;
        }

        // Perform preventive refresh
        SIO_DEBUG("Preventive refresh triggered (avoiding Cloudflare timeout)");
        do_refresh();
    }

    SIO_DEBUG("Refresh timer worker stopped");
}

void SocketIOTransport::do_refresh() {
    if (refresh_in_progress_) {
        SIO_DEBUG("Refresh already in progress, skipping");
        return;
    }

    refresh_in_progress_ = true;
    SIO_DEBUG("Starting preventive refresh...");

    try {
        // 1. Stop heartbeat first
        stop_heartbeat();

        // 2. Close current WebSocket (but keep state)
        std::string saved_session_id = session_id_;
        SIO_DEBUG("Refresh: disconnecting WebSocket...");

        if (connected_) {
            // Send disconnect but don't clear session_id
            send_engine_io_packet(EIO_MESSAGE, std::string(1, SIO_DISCONNECT));
            websocket_.stop();
        }

        connected_ = false;
        socket_io_connected_ = false;
        engine_io_sid_.clear();

        // 3. Wait for connection to fully close
        SIO_DEBUG("Refresh: waiting 2s for cleanup...");
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // 4. Create fresh WebSocket connection
        SIO_DEBUG("Refresh: reconnecting...");

        // Build new WebSocket URL
        std::string ws_url = build_websocket_url();
        SIO_DEBUG("Refresh: new WebSocket URL: " << ws_url);

        websocket_.setUrl(ws_url);

        // Configure TLS
        if (ws_url.substr(0, 4) == "wss:") {
            ix::SocketTLSOptions tls_options;
            tls_options.tls = true;
            if (!ssl_verify_) {
                tls_options.caFile = "NONE";
            }
            websocket_.setTLSOptions(tls_options);
        }

        // Disable automatic reconnection during refresh (we handle it)
        websocket_.disableAutomaticReconnection();

        // Start fresh connection
        websocket_.start();

        // 5. Wait for Socket.IO to connect
        auto start = std::chrono::steady_clock::now();
        while (!socket_io_connected_) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
            if (elapsed >= 15) {
                SIO_DEBUG("Refresh: connection timeout");
                throw std::runtime_error("Refresh connection timeout");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // 6. Verify connection
        if (connected_ && socket_io_connected_) {
            SIO_DEBUG("Refresh: reconnected successfully (sid: " << engine_io_sid_.substr(0, 8) << "...)");
        } else {
            throw std::runtime_error("Refresh failed - not connected after reconnect");
        }

        // Re-enable automatic reconnection
        if (reconnection_enabled_) {
            websocket_.enableAutomaticReconnection();
        }

        // Note: Re-authentication happens automatically in handle_socket_io_packet
        // when SIO_CONNECT is received (if session_id_ is set)

        SIO_DEBUG("Refresh: completed successfully");

    } catch (const std::exception& e) {
        SIO_DEBUG("Refresh failed: " << e.what());
        last_error_ = std::string("Refresh failed: ") + e.what();

        // Try to restore connection
        if (reconnection_enabled_) {
            websocket_.enableAutomaticReconnection();
            websocket_.start();
        }
    }

    refresh_in_progress_ = false;
}

// ============================================================================
// FACTORY FUNCTION UPDATE
// ============================================================================

// This will be defined in http_transport.cpp to avoid duplicate symbols
// std::unique_ptr<Transport> create_transport(...) is defined there

} // namespace transport
} // namespace oliviauth
