/**
 * Olivia Auth - User Registration Example
 *
 * Shows how to register a new user with a license key.
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
    if (!api.initialized()) {
        std::cerr << "Failed to initialize: " << api.last_error() << "\n";
        return 1;
    }

    std::cout << "App initialized!\n";
    std::cout << "\n=== User Registration ===\n";

    // Get registration info
    std::string license_key, username, password;

    std::cout << "License key: ";
    std::getline(std::cin, license_key);

    std::cout << "Choose username: ";
    std::getline(std::cin, username);

    std::cout << "Choose password: ";
    std::getline(std::cin, password);

    // Register the user
    if (api.register_user(license_key, username, password)) {
        std::cout << "\nAccount created successfully!\n";
        std::cout << "You can now login with your username and password.\n";
    } else {
        std::cerr << "\nRegistration failed: " << api.last_error() << "\n";
    }

    api.close();

    return 0;
}
