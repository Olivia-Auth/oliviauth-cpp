/**
 * Olivia Auth - License Authentication Example
 *
 * Shows how to authenticate users with a license key.
 */

#include <oliviauth.h>
#include "xor.h"
#include <iostream>
#include <string>

// =============================================================================
// Copy from Dashboard at https://oliviauth.xyz/dashboard
// =============================================================================
oliviauth::OliviaAuth api(
    RXor("your_owner_id"),            // owner_id
    RXor("YourApp"),                  // app_name
    RXor("1.0.0"),                    // version
    RXor("https://api.oliviauth.xyz/"), // server_url
    RXor("your_client_key"),          // client_key
    RXor("your_server_key"),          // server_key
    "",                               // hash_check
    true,                             // auto_init
    60,                               // heartbeat_interval
    oliviauth::Mode::Socket,          // mode
    true,                             // auto_exit
    ""                                // ssl_sha256
);

int main()
{
    // Check if initialization was successful
    if (!api.initialized()) {
        std::cerr << "Failed to initialize: " << api.last_error() << "\n";
        return 1;
    }

    std::cout << "App initialized successfully!\n";

    // Get license key from user
    std::string license_key;
    std::cout << "Enter your license key: ";
    std::getline(std::cin, license_key);

    // Authenticate with license
    // HWID is generated automatically if not provided
    if (api.license(license_key)) {
        // Check subscription
        if (!api.user().has_subscription()) {
            std::cerr << "Your subscription has expired!\n";
            api.close();
            return 1;
        }

        std::cout << "\nWelcome, " << api.user().username << "!\n";
        std::cout << "IP: " << api.user().ip << "\n";
        std::cout << "HWID: " << api.user().hwid << "\n";
        std::cout << "Subscription: " << api.user().format_time_left() << " remaining\n";

        // Heartbeat runs automatically in the background
        // Your session will be kept alive

        // Your app logic here...
        std::cout << "\nPress Enter to exit...";
        std::cin.get();

    } else {
        std::cerr << "\nAuthentication failed: " << api.last_error() << "\n";
    }

    // Clean up (stops heartbeat)
    api.close();

    return 0;
}
