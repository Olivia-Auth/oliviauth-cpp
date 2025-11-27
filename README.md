# Olivia Auth C++ SDK

Simple and secure C++ SDK for Olivia Auth - Software Licensing Platform.

## Quick Start

```cpp
#include <oliviauth.h>
#include <iostream>

// Configure your app (copy from Dashboard)
oliviauth::OliviaAuth api(
    "your_owner_id",                  // owner_id
    "YourApp",                        // app_name
    "1.0.0",                          // version
    "https://api.oliviauth.xyz/",     // server_url
    "your_client_key",                // client_key
    "your_server_key",                // server_key
    "",                               // hash_check
    true,                             // auto_init
    60,                               // heartbeat_interval
    oliviauth::Mode::Socket,          // mode (Socket or Http)
    true,                             // auto_exit
    ""                                // ssl_sha256
);

int main() {
    // Check connection
    if (!api.initialized()) {
        std::cerr << "Failed to connect: " << api.last_error() << "\n";
        return 1;
    }

    // Authenticate
    if (!api.license("XXXX-XXXX-XXXX-XXXX")) {
        std::cerr << "Auth failed: " << api.last_error() << "\n";
        return 1;
    }

    // Check subscription
    if (!api.user().has_subscription()) {
        std::cerr << "Your subscription has expired!\n";
        return 1;
    }

    std::cout << "Welcome " << api.user().username << "!\n";
    std::cout << "Time left: " << api.user().format_time_left() << "\n";

    // Your app code here...

    api.close();
    return 0;
}
```

## Features

- **Dual Mode**: WebSocket (default) or HTTP - same API for both
- **Automatic Encryption**: RSA-2048 + AES-256-GCM
- **Auto HWID**: Hardware ID generated automatically
- **Auto Heartbeat**: Keeps session alive in background thread
- **Auto Watchdog**: Kills app if authentication is lost (security)
- **Remote Commands**: Server can send commands to clients (WebSocket mode)
- **Subscription Management**: Easy subscription verification
- **2FA Support**: Two-factor authentication

## Modes

### WebSocket Mode (Default)
```cpp
oliviauth::OliviaAuth api(..., oliviauth::Mode::Socket, ...);
```
- Real-time connection
- Server can push commands to client
- More efficient heartbeat
- Recommended for desktop apps

### HTTP Mode
```cpp
oliviauth::OliviaAuth api(..., oliviauth::Mode::Http, ...);
```
- Traditional REST requests
- Simpler, no persistent connection
- Good for scripts and simple tools

Both modes have **identical API** - all functions work the same way!

## Authentication

### With License Key

```cpp
if (api.license("XXXX-XXXX-XXXX-XXXX")) {
    std::cout << "Authenticated as: " << api.user().username << "\n";
}
```

### With Username/Password

```cpp
if (api.login("username", "password")) {
    std::cout << "Login successful!\n";
}

// With 2FA
if (api.login("username", "password", "", "123456")) {
    std::cout << "Login with 2FA successful!\n";
}
```

### Register New User

```cpp
if (api.register_user("LICENSE_KEY", "new_username", "password")) {
    std::cout << "Account created!\n";
}
```

## Subscriptions

```cpp
// Has any active subscription?
if (api.user().has_subscription()) {
    std::cout << "User is active\n";
}

// Has specific subscription level?
if (api.user().has_subscription("1")) {
    std::cout << "Basic plan active\n";
}

// Get plan name
std::string name = api.user().get_subscription_name("1");  // "Basic"

// Time remaining (seconds)
int64_t seconds = api.user().get_subscription_time_left("1");

// Time remaining (formatted)
std::string time_left = api.user().format_time_left("1");  // "30 days"

// List active levels
auto levels = api.user().get_active_subscription_levels();  // {"1", "2"}

// Is lifetime?
if (api.user().is_lifetime("1")) {
    std::cout << "Lifetime subscription!\n";
}
```

## Remote Commands (WebSocket Only)

```cpp
oliviauth::OliviaAuth api(...);

// Register command handler
api.on_command("show_message", [](const std::string& params) {
    std::cout << "Server says: " << params << "\n";
    return "{\"displayed\": true}";
});

// Authenticate
api.license("XXXX-XXXX-XXXX-XXXX");

// Keep connection alive to receive commands
api.wait();
```

## App Variables

```cpp
// Get single variable
std::string download_url = api.get_app_var("download_link");

// Get all variables
auto all_vars = api.get_all_app_vars();
```

## Webhooks

```cpp
std::string result = api.call_webhook(
    "your_webhook_id",
    "{\"action\": \"login\"}",
    "POST"
);
```

## File Downloads

Download files from your server - supports both PUBLIC and PRIVATE downloads.

### Private Downloads (requires authentication + subscription)

```cpp
// Authenticate first
api.license("XXXX-XXXX");

// Download file (automatically uses your session)
api.download_file("download_id", "update.zip");
```

### Public Downloads (no authentication needed)

```cpp
// Download without authentication
OliviaAuth::quick_download(
    "https://api.oliviauth.xyz",
    "download_id",
    "installer.zip"
);
```

### Check Download Info

```cpp
std::string info = api.get_download_info("download_id");
// Returns JSON string with file info
```

## Error Handling

```cpp
#include <oliviauth.h>

try {
    oliviauth::OliviaAuth api(...);
    api.license("XXX");
} catch (const oliviauth::NotInitializedError& e) {
    std::cerr << "App not initialized\n";
} catch (const oliviauth::HWIDMismatchError& e) {
    std::cerr << "HWID mismatch - request reset\n";
} catch (const oliviauth::SubscriptionExpiredError& e) {
    std::cerr << "Subscription expired\n";
} catch (const oliviauth::TwoFactorRequiredError& e) {
    std::cerr << "2FA code required\n";
} catch (const oliviauth::UserBannedError& e) {
    std::cerr << "User is banned\n";
} catch (const oliviauth::AuthenticationError& e) {
    std::cerr << "Error: " << e.what() << "\n";
}

// Or use last_error for simple error handling
if (!api.license("XXX")) {
    std::cerr << "Failed: " << api.last_error() << "\n";
}
```

## User Data

After authentication, `api.user()` contains:

```cpp
api.user().username          // Username
api.user().ip                // User IP address
api.user().hwid              // Hardware ID
api.user().variables         // User variables (map)
api.user().create_date       // Creation date (timestamp)
api.user().last_login        // Last login (timestamp)
```

## Configuration

```cpp
oliviauth::OliviaAuth api(
    "owner_id",               // Required: your owner ID
    "app_name",               // Required: app name
    "version",                // Required: app version
    "server_url",             // Required: server URL (default: https://api.oliviauth.xyz)
    "client_key",             // Required: client encryption key
    "server_key",             // Required: server encryption key
    "hash_check",             // Optional: loader hash verification
    true,                     // Optional: auto_init (default: true)
    60,                       // Optional: heartbeat_interval in seconds (default: 60)
    oliviauth::Mode::Socket,  // Optional: Socket (default) or Http
    true,                     // Optional: auto_exit if auth lost (default: true)
    "ssl_sha256"              // Optional: SSL certificate fingerprint
);
```

## Examples

See the `examples/` folder for complete examples:

| File | Description |
|------|-------------|
| `quick_start.cpp` | Minimal example to get started |
| `license_example.cpp` | License authentication |
| `login_example.cpp` | Username/password login |
| `register_example.cpp` | Register new user |
| `subscription_example.cpp` | Subscription management |
| `complete_example.cpp` | All features demonstrated |

## Available Methods

### OliviaAuth

| Method | Description |
|--------|-------------|
| `init()` | Initialize connection (automatic by default) |
| `license(key, hwid="")` | Authenticate with license |
| `login(user, pass, hwid="", twofa="")` | Login with credentials |
| `register_user(license, user, pass, hwid="")` | Register new user |
| `heartbeat()` | Send heartbeat (automatic) |
| `get_app_var(name)` | Get app variable |
| `get_all_app_vars()` | Get all app variables |
| `call_webhook(id, payload, method)` | Call webhook |
| `on_command(name, handler)` | Register remote command handler |
| `wait()` | Keep connection alive for commands |
| `close()` | Close connection |
| `initialized()` | Check if initialized |
| `authenticated()` | Check if authenticated |
| `last_error()` | Get last error message |

### UserData

| Method | Description |
|--------|-------------|
| `has_subscription(level="")` | Check active subscription |
| `get_subscription_name(level)` | Get subscription name |
| `get_subscription_expiry(level)` | Get expiry timestamp |
| `get_subscription_time_left(level)` | Get seconds remaining |
| `get_active_subscription_levels()` | List active levels |
| `format_time_left(level="")` | Get formatted time remaining |
| `is_lifetime(level)` | Check if lifetime |
| `get_variable(name, default="")` | Get user variable |

## Common Errors

| Error | Solution |
|-------|----------|
| "App not initialized" | Check owner_id, app_name and server_url |
| "Session expired" | Re-initialize the client |
| "HWID mismatch" | Request HWID reset from admin |
| "Subscription expired" | Renew subscription |
| "User is banned" | Contact support |
| "VPN/Proxy detected" | Disable VPN/Proxy |
| "Version mismatch" | Update your application |

## Building

### Requirements

- C++17 or later
- OpenSSL (for encryption)
- CMake 3.14+ (optional)

### Windows (Visual Studio)

1. Open the solution file or create a new project
2. Add `include/` to include directories
3. Add all `.cpp` files from `src/` to your project
4. Link against OpenSSL libraries
5. Build and run

### Linux/macOS

```bash
# Install OpenSSL
# Ubuntu/Debian: sudo apt install libssl-dev
# macOS: brew install openssl

# Compile example
g++ -std=c++17 -I include/ src/*.cpp examples/quick_start.cpp -lssl -lcrypto -lpthread -o myapp
```

## Project Structure

```
oliviauth-cpp/
├── include/
│   └── oliviauth.h      # Main header (include this)
├── src/
│   ├── oliviauth.cpp    # Main implementation
│   ├── crypto.cpp       # Encryption
│   ├── http.cpp         # HTTP client
│   ├── hwid.cpp         # Hardware ID
│   └── user.cpp         # User data
├── deps/                # Dependencies (json, httplib, etc)
├── examples/            # Example code
└── README.md
```

## License

MIT License - see LICENSE file for details.
