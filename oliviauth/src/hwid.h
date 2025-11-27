/**
 * @file hwid.h
 * @brief Internal HWID generation for Olivia Auth
 *
 * DO NOT include this file directly. Use oliviauth.h instead.
 */

#pragma once

#include <string>

namespace oliviauth {
namespace hwid {

/**
 * @brief Get CPU ID string
 * @return CPU identifier or empty on failure
 */
std::string get_cpu_id();

/**
 * @brief Get primary MAC address
 * @return MAC address (uppercase, no separators) or empty on failure
 */
std::string get_mac_address();

/**
 * @brief Get disk serial number
 * @return Disk serial or empty on failure
 */
std::string get_disk_serial();

/**
 * @brief Get machine GUID (Windows) or UUID (macOS/Linux)
 * @return Machine unique identifier or empty on failure
 */
std::string get_machine_guid();

/**
 * @brief Get hostname
 * @return Hostname or empty on failure
 */
std::string get_hostname();

/**
 * @brief Get system info string (OS-Arch-Processor)
 * @return System info or empty on failure
 */
std::string get_system_info();

/**
 * @brief Generate complete hardware ID
 *
 * Combines: MAC:Hostname:SystemInfo
 * Then hashes with SHA-256 and returns uppercase hex.
 *
 * This matches the Python SDK behavior.
 *
 * @return 64-character hexadecimal HWID
 */
std::string generate();

/**
 * @brief Validate HWID format
 * @param hwid HWID to validate
 * @param min_length Minimum length (default: 10)
 * @return true if valid format
 */
bool validate(const std::string& hwid, size_t min_length = 10);

} // namespace hwid
} // namespace oliviauth
