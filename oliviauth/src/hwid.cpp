/**
 * @file hwid.cpp
 * @brief Hardware ID generation implementation
 *
 * Generates a unique hardware identifier matching Python SDK behavior.
 * Supports Windows, macOS, and Linux.
 */

#include "hwid.h"
#include "crypto.h"
#include "xor.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstring>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <iphlpapi.h>
    #include <intrin.h>
    #pragma comment(lib, "iphlpapi.lib")
#elif defined(__APPLE__)
    #include <sys/sysctl.h>
    #include <sys/socket.h>
    #include <net/if.h>
    #include <net/if_dl.h>
    #include <ifaddrs.h>
    #include <unistd.h>
    #include <IOKit/IOKitLib.h>
    #include <CoreFoundation/CoreFoundation.h>
#else
    // Linux
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <sys/utsname.h>
    #include <net/if.h>
    #include <unistd.h>
    #include <fstream>
    #include <dirent.h>
#endif

namespace oliviauth {
namespace hwid {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static std::string to_uppercase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return result;
}

static std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

// ============================================================================
// WINDOWS IMPLEMENTATION
// ============================================================================

#ifdef _WIN32

std::string get_cpu_id() {
    int cpuInfo[4] = {0};

    // Get vendor string
    __cpuid(cpuInfo, 0);
    char vendor[13];
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
    vendor[12] = '\0';

    // Get processor info
    __cpuid(cpuInfo, 1);

    std::stringstream ss;
    ss << vendor << "-";
    ss << std::hex << cpuInfo[0] << "-" << cpuInfo[3];

    return to_uppercase(ss.str());
}

std::string get_mac_address() {
    ULONG bufLen = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);

    if (GetAdaptersInfo(pAdapterInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);
    }

    std::string result;

    if (GetAdaptersInfo(pAdapterInfo, &bufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;

        // Find first non-virtual adapter
        while (pAdapter) {
            if (pAdapter->AddressLength == 6) {
                std::stringstream ss;
                for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                    ss << std::hex << std::setfill('0') << std::setw(2)
                       << (int)pAdapter->Address[i];
                }
                result = to_uppercase(ss.str());
                break;
            }
            pAdapter = pAdapter->Next;
        }
    }

    free(pAdapterInfo);
    return result;
}

std::string get_disk_serial() {
    char volumeName[MAX_PATH + 1] = {0};
    char fileSystemName[MAX_PATH + 1] = {0};
    DWORD serialNumber = 0;
    DWORD maxComponentLen = 0;
    DWORD fileSystemFlags = 0;

    if (GetVolumeInformationA(
            RXor("C:\\"),
            volumeName, MAX_PATH,
            &serialNumber,
            &maxComponentLen,
            &fileSystemFlags,
            fileSystemName, MAX_PATH)) {
        std::stringstream ss;
        ss << std::hex << serialNumber;
        return to_uppercase(ss.str());
    }

    return "";
}

std::string get_machine_guid() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      RXor("SOFTWARE\\Microsoft\\Cryptography"),
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        char guid[256] = {0};
        DWORD size = sizeof(guid);
        DWORD type = REG_SZ;

        if (RegQueryValueExA(hKey, RXor("MachineGuid"), nullptr, &type,
                             (LPBYTE)guid, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::string(guid);
        }
        RegCloseKey(hKey);
    }
    return "";
}

std::string get_hostname() {
    char buffer[256] = {0};
    DWORD size = sizeof(buffer);
    if (GetComputerNameA(buffer, &size)) {
        return std::string(buffer);
    }
    return "";
}

std::string get_system_info() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    std::stringstream ss;
    ss << RXor("Windows-");

    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: ss << RXor("x64"); break;
        case PROCESSOR_ARCHITECTURE_INTEL: ss << RXor("x86"); break;
        case PROCESSOR_ARCHITECTURE_ARM64: ss << RXor("ARM64"); break;
        default: ss << RXor("Unknown"); break;
    }

    return ss.str();
}

// ============================================================================
// MACOS IMPLEMENTATION
// ============================================================================

#elif defined(__APPLE__)

std::string get_cpu_id() {
    char buffer[256] = {0};
    size_t size = sizeof(buffer);

    if (sysctlbyname(RXor("machdep.cpu.brand_string"), buffer, &size, nullptr, 0) == 0) {
        return std::string(buffer);
    }
    return "";
}

std::string get_mac_address() {
    struct ifaddrs* iflist;
    if (getifaddrs(&iflist) != 0) return "";

    std::string result;

    for (struct ifaddrs* cur = iflist; cur; cur = cur->ifa_next) {
        if (cur->ifa_addr && cur->ifa_addr->sa_family == AF_LINK) {
            // Skip loopback
            if (strcmp(cur->ifa_name, RXor("lo0")) == 0) continue;

            struct sockaddr_dl* sdl = (struct sockaddr_dl*)cur->ifa_addr;
            if (sdl->sdl_alen == 6) {
                unsigned char* mac = (unsigned char*)LLADDR(sdl);
                std::stringstream ss;
                for (int i = 0; i < 6; i++) {
                    ss << std::hex << std::setfill('0') << std::setw(2)
                       << (int)mac[i];
                }
                result = to_uppercase(ss.str());
                break;
            }
        }
    }

    freeifaddrs(iflist);
    return result;
}

std::string get_disk_serial() {
    // On macOS, use IOKit to get disk serial
    io_service_t service = IOServiceGetMatchingService(
        kIOMasterPortDefault,
        IOServiceMatching("IOPlatformExpertDevice")
    );

    if (service) {
        CFStringRef serialRef = (CFStringRef)IORegistryEntryCreateCFProperty(
            service,
            CFSTR("IOPlatformSerialNumber"),
            kCFAllocatorDefault,
            0
        );

        std::string result;
        if (serialRef) {
            char buffer[256];
            if (CFStringGetCString(serialRef, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
                result = buffer;
            }
            CFRelease(serialRef);
        }

        IOObjectRelease(service);
        return result;
    }

    return "";
}

std::string get_machine_guid() {
    // On macOS, use IOPlatformUUID
    io_service_t service = IOServiceGetMatchingService(
        kIOMasterPortDefault,
        IOServiceMatching("IOPlatformExpertDevice")
    );

    if (service) {
        CFStringRef uuidRef = (CFStringRef)IORegistryEntryCreateCFProperty(
            service,
            CFSTR("IOPlatformUUID"),
            kCFAllocatorDefault,
            0
        );

        std::string result;
        if (uuidRef) {
            char buffer[256];
            if (CFStringGetCString(uuidRef, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
                result = buffer;
            }
            CFRelease(uuidRef);
        }

        IOObjectRelease(service);
        return result;
    }

    return "";
}

std::string get_hostname() {
    char buffer[256] = {0};
    if (gethostname(buffer, sizeof(buffer)) == 0) {
        return std::string(buffer);
    }
    return "";
}

std::string get_system_info() {
    char buffer[256] = {0};
    size_t size = sizeof(buffer);

    std::string machine;
    if (sysctlbyname(RXor("hw.machine"), buffer, &size, nullptr, 0) == 0) {
        machine = buffer;
    }

    return std::string(RXor("macOS-")) + machine;
}

// ============================================================================
// LINUX IMPLEMENTATION
// ============================================================================

#else

std::string get_cpu_id() {
    std::ifstream cpuinfo(RXor("/proc/cpuinfo"));
    if (!cpuinfo) return "";

    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find(RXor("model name")) != std::string::npos) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                return trim(line.substr(pos + 1));
            }
        }
    }

    return "";
}

std::string get_mac_address() {
    std::string result;

    DIR* dir = opendir(RXor("/sys/class/net"));
    if (!dir) return "";

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        if (strcmp(entry->d_name, RXor("lo")) == 0) continue;

        std::string path = RXor("/sys/class/net/");
        path += entry->d_name;
        path += RXor("/address");

        std::ifstream file(path);
        if (file) {
            std::string mac;
            std::getline(file, mac);
            // Remove colons and convert to uppercase
            mac.erase(std::remove(mac.begin(), mac.end(), ':'), mac.end());
            result = to_uppercase(mac);
            break;
        }
    }

    closedir(dir);
    return result;
}

std::string get_disk_serial() {
    // Try to read from /sys/block/*/device/serial
    DIR* dir = opendir(RXor("/sys/block"));
    if (!dir) return "";

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        std::string path = RXor("/sys/block/");
        path += entry->d_name;
        path += RXor("/device/serial");

        std::ifstream file(path);
        if (file) {
            std::string serial;
            std::getline(file, serial);
            if (!serial.empty()) {
                closedir(dir);
                return trim(serial);
            }
        }
    }

    closedir(dir);
    return "";
}

std::string get_machine_guid() {
    std::ifstream file(RXor("/etc/machine-id"));
    if (!file) {
        file.open(RXor("/var/lib/dbus/machine-id"));
    }

    if (file) {
        std::string guid;
        std::getline(file, guid);
        return trim(guid);
    }

    return "";
}

std::string get_hostname() {
    char buffer[256] = {0};
    if (gethostname(buffer, sizeof(buffer)) == 0) {
        return std::string(buffer);
    }
    return "";
}

std::string get_system_info() {
    struct utsname info;
    if (uname(&info) == 0) {
        return std::string(info.sysname) + "-" + info.machine;
    }
    return RXor("Linux");
}

#endif

// ============================================================================
// MAIN HWID GENERATION (matches Python SDK)
// ============================================================================

std::string generate() {
    // Get components (matching Python SDK approach)
    std::string mac = get_mac_address();
    std::string hostname = get_hostname();
    std::string system_info = get_system_info();

    // If MAC is empty, try alternatives
    if (mac.empty()) {
        mac = get_machine_guid();
    }

    // Combine: MAC:Hostname:SystemInfo (Python SDK format)
    std::string combined = mac + ":" + hostname + ":" + system_info;

    // Hash with SHA-256
    std::string hash = crypto::sha256_hex(combined);

    // Return uppercase (Python SDK format)
    return to_uppercase(hash);
}

bool validate(const std::string& hwid, size_t min_length) {
    if (hwid.empty() || hwid.length() < min_length) {
        return false;
    }

    // Check if all characters are valid hex
    for (char c : hwid) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }

    return true;
}

} // namespace hwid
} // namespace oliviauth
