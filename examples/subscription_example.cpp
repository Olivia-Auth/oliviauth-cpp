/**
 * Olivia Auth - Subscription Management Example
 *
 * Shows how to check and manage user subscriptions.
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

    std::string license_key;
    std::cout << "Enter your license key: ";
    std::getline(std::cin, license_key);

    if (!api.license(license_key)) {
        std::cerr << "Authentication failed: " << api.last_error() << "\n";
        return 1;
    }

    std::cout << "\nWelcome, " << api.user().username << "!\n";

    std::cout << "\n========================================\n";
    std::cout << "SUBSCRIPTION STATUS\n";
    std::cout << "========================================\n";

    // Check if user has ANY active subscription
    if (api.user().has_subscription()) {
        std::cout << "Status: ACTIVE\n";

        // Get all active subscription levels
        auto active_levels = api.user().get_active_subscription_levels();
        std::cout << "Active plans: ";
        for (size_t i = 0; i < active_levels.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << active_levels[i];
        }
        std::cout << "\n";

        // Show details for each subscription
        std::cout << "\nPlan Details:\n";
        for (const auto& level : active_levels) {
            std::string name = api.user().get_subscription_name(level);
            std::string time_left = api.user().format_time_left(level);
            bool is_lifetime = api.user().is_lifetime(level);

            std::cout << "  Level " << level << ": " << name << "\n";
            std::cout << "    Time remaining: " << time_left << "\n";
            if (is_lifetime) {
                std::cout << "    Type: Lifetime (never expires)\n";
            }
        }

    } else {
        std::cout << "Status: NO ACTIVE SUBSCRIPTION\n";
        std::cerr << "\nYour subscription has expired!\n";
        api.close();
        return 1;
    }

    std::cout << "\n========================================\n";
    std::cout << "FEATURE ACCESS\n";
    std::cout << "========================================\n";

    // Example: Control features based on subscription level
    if (api.user().has_subscription("1")) {
        std::cout << "Basic features: UNLOCKED\n";
    } else {
        std::cout << "Basic features: LOCKED\n";
    }

    if (api.user().has_subscription("2")) {
        std::cout << "Premium features: UNLOCKED\n";
    } else {
        std::cout << "Premium features: LOCKED\n";
    }

    if (api.user().has_subscription("3")) {
        std::cout << "VIP features: UNLOCKED\n";
    } else {
        std::cout << "VIP features: LOCKED\n";
    }

    // Example: Show different content based on subscription
    std::cout << "\n========================================\n";
    std::cout << "CONTENT ACCESS\n";
    std::cout << "========================================\n";

    if (api.user().has_subscription("3")) {
        std::cout << "Welcome VIP member! You have access to everything.\n";
    } else if (api.user().has_subscription("2")) {
        std::cout << "Welcome Premium member! Upgrade to VIP for more features.\n";
    } else if (api.user().has_subscription("1")) {
        std::cout << "Welcome! Consider upgrading for more features.\n";
    } else {
        std::cout << "Please purchase a subscription to access features.\n";
    }

    api.close();

    return 0;
}
