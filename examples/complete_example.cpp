/**
 * Olivia Auth - Complete Example
 *
 * Demonstrates all features of the Olivia Auth C++ SDK.
 *
 * This example works with both modes - just change the mode parameter:
 *   - Mode::Socket (default) - WebSocket with remote commands support
 *   - Mode::Http - Traditional HTTP requests
 *
 * Both modes have the SAME API - all functions work identically!
 */

#include <oliviauth.h>
#include "xor.h"
#include <iostream>
#include <string>
#include <ctime>

#ifdef _WIN32
    #include <windows.h>
    #define CLEAR_SCREEN() system("cls")
#else
    #define CLEAR_SCREEN() system("clear")
#endif

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
    oliviauth::Mode::Socket,          // mode (Socket = default, like Python)
    true,                             // auto_exit
    ""                                // ssl_sha256
);

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

void print_header(const std::string& title) {
    std::cout << "\n==================================================\n";
    std::cout << " " << title << "\n";
    std::cout << "==================================================\n";
}

void pause() {
    std::cout << "\nPress ENTER to continue...";
    std::cin.ignore();
    std::cin.get();
}

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    print_header("OliviaAuth Complete Example");

    // =========================================
    // 1. INITIALIZATION
    // =========================================
    print_header("1. Initialization");

    if (!api.initialized()) {
        std::cerr << "Failed to initialize: " << api.last_error() << "\n";
        return 1;
    }

    std::cout << "App initialized successfully!\n";
    std::cout << "Mode: " << (api.mode() == oliviauth::Mode::Socket ? "Socket" : "HTTP") << "\n";
    std::cout << "Session ID: " << api.session_id().substr(0, 20) << "...\n";

    // =========================================
    // 2. AUTHENTICATION
    // =========================================
    print_header("2. Authentication");

    std::cout << "Choose authentication method:\n";
    std::cout << "1. License key\n";
    std::cout << "2. Username/password\n";
    std::cout << "Enter choice (1 or 2): ";

    std::string choice;
    std::getline(std::cin, choice);

    bool success = false;

    if (choice == "1") {
        std::string license_key;
        std::cout << "License key: ";
        std::getline(std::cin, license_key);
        success = api.license(license_key);
    } else {
        std::string username, password;
        std::cout << "Username: ";
        std::getline(std::cin, username);
        std::cout << "Password: ";
        std::getline(std::cin, password);
        success = api.login(username, password);
    }

    if (!success) {
        std::cerr << "Authentication failed: " << api.last_error() << "\n";
        return 1;
    }

    std::cout << "\nAuthenticated as: " << api.user().username << "\n";
    std::cout << "IP Address: " << api.user().ip << "\n";
    std::cout << "HWID: " << api.user().hwid << "\n";
    std::cout << "Account created: " << api.user().create_date << "\n";
    std::cout << "Last login: " << api.user().last_login << "\n";

    // =========================================
    // 3. SUBSCRIPTIONS
    // =========================================
    print_header("3. Subscriptions");

    // Check if user has ANY active subscription
    if (!api.user().has_subscription()) {
        std::cout << "No active subscriptions\n";
        std::cerr << "\nYour subscription has expired!\n";
        api.close();
        return 1;
    }

    auto active = api.user().get_active_subscription_levels();
    std::cout << "Active subscription levels: ";
    for (size_t i = 0; i < active.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << active[i];
    }
    std::cout << "\n";

    for (const auto& level : active) {
        std::string name = api.user().get_subscription_name(level);
        std::string time_left = api.user().format_time_left(level);
        std::cout << "  - Level " << level << " (" << name << "): " << time_left << "\n";
    }

    // Check specific subscription levels
    std::cout << "\nFeature access:\n";
    std::cout << "  Basic (level 1): " << (api.user().has_subscription("1") ? "Yes" : "No") << "\n";
    std::cout << "  Premium (level 2): " << (api.user().has_subscription("2") ? "Yes" : "No") << "\n";
    std::cout << "  VIP (level 3): " << (api.user().has_subscription("3") ? "Yes" : "No") << "\n";

    // =========================================
    // 4. USER VARIABLES
    // =========================================
    print_header("4. User Variables");

    auto user_vars = api.user().variables;
    if (!user_vars.empty()) {
        std::cout << "Your variables:\n";
        for (const auto& [key, value] : user_vars) {
            std::cout << "  " << key << ": " << value << "\n";
        }
    } else {
        std::cout << "No user variables set\n";
    }

    // =========================================
    // 5. APP VARIABLES
    // =========================================
    print_header("5. App Variables");

    auto app_vars = api.get_all_app_vars();
    if (!app_vars.empty()) {
        std::cout << "Available app variables:\n";
        for (const auto& [key, value] : app_vars) {
            std::cout << "  " << key << ": " << value << "\n";
        }
    } else {
        std::cout << "No app variables or unable to retrieve\n";
    }

    // =========================================
    // 6. WEBHOOKS
    // =========================================
    print_header("6. Webhooks (if configured)");

    // Example webhook call (commented out - configure your own)
    // std::string result = api.call_webhook("your_webhook_id", "{\"action\": \"test\"}");
    // if (!result.empty()) {
    //     std::cout << "Webhook response: " << result << "\n";
    // }
    std::cout << "Webhook example (configure your own webhook ID)\n";

    // =========================================
    // 7. HEARTBEAT
    // =========================================
    print_header("7. Heartbeat");

    std::cout << "Heartbeat runs automatically (default: 60 seconds)\n";

    // Manual heartbeat (not needed, just for demonstration)
    if (api.heartbeat()) {
        std::cout << "Manual heartbeat: Success\n";
    }

    // =========================================
    // 8. SESSION INFO
    // =========================================
    print_header("8. Session Status");

    std::cout << "Initialized: " << (api.initialized() ? "Yes" : "No") << "\n";
    std::cout << "Authenticated: " << (api.authenticated() ? "Yes" : "No") << "\n";
    std::cout << "User: " << api.user().username << "\n";

    // =========================================
    // CLEANUP
    // =========================================
    print_header("Cleanup");

    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    std::cout << "Closing connection and stopping heartbeat...\n";

    api.close();
    std::cout << "Done! Connection closed.\n";

    return 0;
}
