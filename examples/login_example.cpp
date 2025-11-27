/**
 * Olivia Auth - Login Example
 *
 * Shows how to authenticate users with username/password.
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

    // Get credentials
    std::string username, password;
    std::cout << "Username: ";
    std::getline(std::cin, username);
    std::cout << "Password: ";
    std::getline(std::cin, password);

    try {
        if (api.login(username, password)) {
            // Check subscription
            if (!api.user().has_subscription()) {
                std::cerr << "Your subscription has expired!\n";
                api.close();
                return 1;
            }

            std::cout << "\nWelcome back, " << api.user().username << "!\n";
            std::cout << "Subscription: " << api.user().format_time_left() << " remaining\n";

            // Your app logic here...
            std::cout << "\nPress Enter to exit...";
            std::cin.get();

        } else {
            // Check if 2FA is required
            if (api.last_error().find("2FA") != std::string::npos ||
                api.last_error().find("two") != std::string::npos) {

                std::string code;
                std::cout << "Enter 2FA code: ";
                std::getline(std::cin, code);

                if (api.login(username, password, "", code)) {
                    // Check subscription
                    if (!api.user().has_subscription()) {
                        std::cerr << "Your subscription has expired!\n";
                        api.close();
                        return 1;
                    }

                    std::cout << "\nWelcome back, " << api.user().username << "!\n";
                    std::cout << "Subscription: " << api.user().format_time_left() << " remaining\n";
                } else {
                    std::cerr << "\nLogin failed: " << api.last_error() << "\n";
                }
            } else {
                std::cerr << "\nLogin failed: " << api.last_error() << "\n";
            }
        }

    } catch (const oliviauth::TwoFactorRequiredError& e) {
        // Handle 2FA if enabled on account
        std::string code;
        std::cout << "Enter 2FA code: ";
        std::getline(std::cin, code);

        if (api.login(username, password, "", code)) {
            // Check subscription
            if (!api.user().has_subscription()) {
                std::cerr << "Your subscription has expired!\n";
                api.close();
                return 1;
            }

            std::cout << "\nWelcome back, " << api.user().username << "!\n";
        } else {
            std::cerr << "\nLogin failed: " << api.last_error() << "\n";
        }
    }

    api.close();

    return 0;
}
