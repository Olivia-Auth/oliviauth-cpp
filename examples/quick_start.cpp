/**
 * Olivia Auth - Quick Start
 *
 * Minimal example to integrate authentication into your app.
 * Everything runs automatically in the background:
 *   - Heartbeat (keeps session alive)
 *   - Watchdog (kills app if auth is lost - prevents unauthorized usage)
 *   - Encryption (all data is encrypted automatically)
 *
 * Just copy this pattern into your project!
 */

#include <oliviauth.h>
#include "xor.h"
#include <iostream>
#include <string>

// =============================================================================
// STEP 1: Copy from Dashboard at https://oliviauth.xyz/dashboard
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
    oliviauth::Mode::Socket,          // mode (Socket = default, like Python)
    true,                             // auto_exit
    ""                                // ssl_sha256
);

int main()
{
    // Check if connected to server
    if (!api.initialized()) {
        std::cerr << "Could not connect to server: " << api.last_error() << "\n";
        return 1;
    }

    // =============================================================================
    // STEP 2: Authenticate
    // =============================================================================
    std::string license_key;
    std::cout << "Enter license key: ";
    std::getline(std::cin, license_key);

    std::cerr << ">>> Calling api.license()...\n";
    if (!api.license(license_key)) {
        std::cerr << "Authentication failed: " << api.last_error() << "\n";
        api.close();
        return 1;
    }
    std::cerr << ">>> api.license() returned true!\n";

    // =============================================================================
    // STEP 3: Check subscription
    // =============================================================================
    std::cerr << ">>> About to call api.user()...\n";
    const auto& user = api.user();
    std::cerr << ">>> Got user reference, username=" << user.username << "\n";
    std::cerr << ">>> About to call has_subscription()...\n";
    if (!user.has_subscription()) {
        std::cerr << "Your subscription has expired!\n";
        api.close();
        return 1;
    }

    // =============================================================================
    // DONE! Your app is now protected.
    // =============================================================================
    // From this point on:
    //   - Heartbeat runs automatically in background
    //   - If session expires or is killed by admin, app exits automatically
    //   - You don't need to do anything else!

    std::cout << "\nWelcome " << api.user().username << "!\n";
    std::cout << "Subscription: " << api.user().format_time_left() << " remaining\n\n";

    // =============================================================================
    // YOUR APP CODE BELOW
    // =============================================================================
    // The app will automatically exit if:
    //   - Session expires
    //   - Admin kills the session from dashboard
    //   - License is revoked
    //
    // You can set a callback to run before exit:
    //   api.set_on_session_expired([]() { std::cout << "Session expired! Closing...\n"; });

    while (true) {
        std::string command;
        std::cout << "Your app is running. Type 'quit' to exit: ";
        std::getline(std::cin, command);

        if (command == "quit") {
            break;
        }

        // Your app logic here...
    }

    // Clean exit
    api.close();

    return 0;
}
