/**
 * Download Example - Shows how to download files
 *
 * TWO TYPES OF DOWNLOADS:
 * 1. PUBLIC downloads - Anyone can download (no auth needed)
 * 2. PRIVATE downloads - Requires login + active subscription
 */

#include <oliviauth.h>
#include "xor.h"
#include <iostream>

using namespace oliviauth;

int main() {
    // =========================================================================
    // Example 1: PRIVATE DOWNLOAD (requires authentication)
    // =========================================================================

    std::cout << "=== PRIVATE DOWNLOAD EXAMPLE ===\n\n";

    // Configure your app
    OliviaAuth api(
        RXor("your_owner_id"),        // owner_id
        RXor("YourApp"),              // app_name
        RXor("1.0.0"),                // version
        RXor("https://api.oliviauth.xyz"), // server_url
        RXor("your_client_key"),      // client_key
        RXor("your_server_key")       // server_key
    );

    // Authenticate first
    if (api.license(RXor("XXXX-XXXX-XXXX-XXXX"))) {
        std::cout << "✓ Logged in as: " << api.user().username << "\n\n";

        // Check if download requires authentication (optional)
        std::string download_id = "your_download_id";  // Get this from your dashboard

        std::string info = api.get_download_info(download_id);
        if (!info.empty()) {
            std::cout << "File info: " << info << "\n\n";
        }

        // Download the file (uses your session automatically)
        if (api.download_file(download_id, "downloaded_file.zip")) {
            std::cout << "\n✓ Download successful!\n";
        } else {
            std::cout << "\n✗ Download failed: " << api.last_error() << "\n";
        }
    } else {
        std::cout << "✗ Authentication failed: " << api.last_error() << "\n";
    }

    api.close();

    // =========================================================================
    // Example 2: PUBLIC DOWNLOAD (no authentication needed)
    // =========================================================================

    std::cout << "\n\n=== PUBLIC DOWNLOAD EXAMPLE ===\n\n";

    // For public files, you don't even need to authenticate!
    // Just use the quick_download static method

    if (OliviaAuth::quick_download(
        "https://api.oliviauth.xyz",
        "public_download_id",  // Get this from your dashboard
        "public_file.zip"
    )) {
        std::cout << "✓ Public download successful!\n";
    } else {
        std::cout << "✗ Public download failed\n";
    }

    // =========================================================================
    // Example 3: COMPLETE WORKFLOW
    // =========================================================================

    std::cout << "\n\n=== COMPLETE WORKFLOW ===\n\n";

    OliviaAuth api2(
        "your_owner_id",
        "YourApp",
        "1.0.0",
        "https://api.oliviauth.xyz",
        "your_client_key",
        "your_server_key"
    );

    // Login
    if (api2.login("username", "password")) {
        std::cout << "✓ Logged in as: " << api2.user().username << "\n";

        // Check subscription
        if (!api2.user().has_subscription()) {
            std::cout << "✗ No active subscription - cannot download private files\n";
        } else {
            std::cout << "✓ Subscription active: " << api2.user().format_time_left() << "\n";

            // Download private file
            std::cout << "\nDownloading private file...\n";
            if (api2.download_file("private_download_id", "premium_content.zip")) {
                std::cout << "✓ Download complete!\n";
            }
        }
    }

    api2.close();

    // =========================================================================
    // USAGE SUMMARY
    // =========================================================================

    std::cout << "\n\n=== USAGE SUMMARY ===\n";
    std::cout << R"(
For PRIVATE downloads (requires auth + subscription):
    OliviaAuth api(...);
    api.license("XXXX");  // or api.login("user", "pass")
    api.download_file("download_id", "save_path.zip");

For PUBLIC downloads (no auth needed):
    OliviaAuth::quick_download(
        "https://...",
        "download_id",
        "file.zip"
    );
)" << std::endl;

    return 0;
}
