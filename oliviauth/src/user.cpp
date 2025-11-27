/**
 * @file user.cpp
 * @brief UserData class implementation
 */

#include "../include/oliviauth.h"
#include "json_utils.h"

#include <chrono>
#include <ctime>
#include <sstream>
#include <algorithm>
#include <iostream>

using json = nlohmann::json;

namespace oliviauth {

// Debug helper (uses same global flag from oliviauth.cpp)
// is_debug_mode() is declared in oliviauth namespace
#define USER_DEBUG(msg) if (oliviauth::is_debug_mode()) std::cerr << "[DEBUG] [USER] " << msg << std::endl

// ============================================================================
// IMPLEMENTATION STRUCTURE
// ============================================================================

struct UserData::Impl {
    std::string raw_json;
    json data;

    // Subscriptions: level -> {name, expiry}
    struct SubscriptionInfo {
        std::string name;
        int64_t expiry = 0;  // Unix timestamp, -1 for lifetime
    };
    std::map<std::string, SubscriptionInfo> subscriptions;

    bool valid = false;

    void parse(const std::string& json_str) {
        raw_json = json_str;
        try {
            data = json::parse(json_str);
            valid = true;

            USER_DEBUG("Parsing user data...");
            USER_DEBUG("Raw JSON: " + json_str.substr(0, 200) + "...");

            // Parse subscriptions
            if (data.contains("subscriptions")) {
                USER_DEBUG("Found 'subscriptions' field");
                if (data["subscriptions"].is_object()) {
                    USER_DEBUG("Subscriptions is an object with " + std::to_string(data["subscriptions"].size()) + " entries");
                    for (auto& [level, info] : data["subscriptions"].items()) {
                        USER_DEBUG("Parsing subscription level: " + level);
                        SubscriptionInfo sub;
                        if (info.is_object()) {
                            sub.name = json_value<std::string>(info, "name");
                            sub.expiry = json_value<int64_t>(info, "expiry");
                            USER_DEBUG("  name: " + sub.name + ", expiry: " + std::to_string(sub.expiry));
                        } else {
                            USER_DEBUG("  WARNING: subscription info is not an object!");
                        }
                        subscriptions[level] = sub;
                    }
                } else {
                    USER_DEBUG("WARNING: 'subscriptions' is not an object, type: " + std::string(data["subscriptions"].type_name()));
                }
            } else {
                USER_DEBUG("WARNING: No 'subscriptions' field found in user data");
            }

            USER_DEBUG("Total subscriptions parsed: " + std::to_string(subscriptions.size()));
        } catch (const std::exception& e) {
            USER_DEBUG("ERROR parsing user data: " + std::string(e.what()));
            valid = false;
        } catch (...) {
            USER_DEBUG("ERROR parsing user data: unknown exception");
            valid = false;
        }
    }
};

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

UserData::UserData()
    : impl_(std::make_unique<Impl>())
{
}

UserData::UserData(const std::string& json_data)
    : impl_(std::make_unique<Impl>())
{
    impl_->parse(json_data);

    if (impl_->valid) {
        USER_DEBUG(">>> Extracting fields using null-safe json_value...");

        username = json_value<std::string>(impl_->data, "username");
        hwid = json_value<std::string>(impl_->data, "hwid");
        ip = json_value<std::string>(impl_->data, "ip");
        create_date = json_value<int64_t>(impl_->data, "createdate");
        last_login = json_value<int64_t>(impl_->data, "lastlogin");

        USER_DEBUG(">>> username=" + username + ", hwid=" + hwid + ", ip=" + ip);

        // Parse user variables
        if (impl_->data.contains("userVars") && !impl_->data["userVars"].is_null() && impl_->data["userVars"].is_object()) {
            for (auto& [key, value] : impl_->data["userVars"].items()) {
                if (value.is_null()) {
                    variables[key] = "";
                } else if (value.is_string()) {
                    variables[key] = value.get<std::string>();
                } else {
                    variables[key] = value.dump();
                }
            }
        }
        USER_DEBUG(">>> UserData constructor complete");
    }
}

UserData::~UserData() {
    USER_DEBUG(">>> UserData destructor called for username=" + username);
}

// Copy constructor
UserData::UserData(const UserData& other)
    : username(other.username)
    , hwid(other.hwid)
    , ip(other.ip)
    , create_date(other.create_date)
    , last_login(other.last_login)
    , variables(other.variables)
    , impl_(std::make_unique<Impl>())
{
    if (other.impl_) {
        impl_->raw_json = other.impl_->raw_json;
        impl_->data = other.impl_->data;
        impl_->subscriptions = other.impl_->subscriptions;
        impl_->valid = other.impl_->valid;
    }
}

// Copy assignment operator
UserData& UserData::operator=(const UserData& other) {
    if (this != &other) {
        username = other.username;
        hwid = other.hwid;
        ip = other.ip;
        create_date = other.create_date;
        last_login = other.last_login;
        variables = other.variables;

        if (!impl_) {
            impl_ = std::make_unique<Impl>();
        }

        if (other.impl_) {
            impl_->raw_json = other.impl_->raw_json;
            impl_->data = other.impl_->data;
            impl_->subscriptions = other.impl_->subscriptions;
            impl_->valid = other.impl_->valid;
        } else {
            impl_->raw_json.clear();
            impl_->data = json();
            impl_->subscriptions.clear();
            impl_->valid = false;
        }
    }
    return *this;
}

// Move constructor
UserData::UserData(UserData&& other) noexcept
    : username(std::move(other.username))
    , hwid(std::move(other.hwid))
    , ip(std::move(other.ip))
    , create_date(other.create_date)
    , last_login(other.last_login)
    , variables(std::move(other.variables))
    , impl_(std::move(other.impl_))
{
}

// Move assignment operator
UserData& UserData::operator=(UserData&& other) noexcept {
    USER_DEBUG(">>> Move assignment operator called");
    if (this != &other) {
        USER_DEBUG(">>> Moving username: " + other.username);
        username = std::move(other.username);
        USER_DEBUG(">>> Moving hwid");
        hwid = std::move(other.hwid);
        USER_DEBUG(">>> Moving ip");
        ip = std::move(other.ip);
        USER_DEBUG(">>> Moving create_date");
        create_date = other.create_date;
        USER_DEBUG(">>> Moving last_login");
        last_login = other.last_login;
        USER_DEBUG(">>> Moving variables");
        variables = std::move(other.variables);
        USER_DEBUG(">>> Moving impl_");
        impl_ = std::move(other.impl_);
        USER_DEBUG(">>> Move assignment complete");
    }
    return *this;
}

// ============================================================================
// SUBSCRIPTION METHODS
// ============================================================================

bool UserData::has_subscription(const std::string& level) const {
    if (!impl_ || !impl_->valid) {
        USER_DEBUG("has_subscription: impl_ or valid is false");
        return false;
    }

    auto now = std::chrono::system_clock::now();
    auto now_ts = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();

    USER_DEBUG("has_subscription: checking level='" + level + "', now_ts=" + std::to_string(now_ts));
    USER_DEBUG("has_subscription: total subscriptions count=" + std::to_string(impl_->subscriptions.size()));

    if (level.empty()) {
        // Check if any subscription is active
        for (const auto& [lvl, sub] : impl_->subscriptions) {
            USER_DEBUG("  Checking level '" + lvl + "': expiry=" + std::to_string(sub.expiry));
            if (sub.expiry == -1 || sub.expiry > now_ts) {
                USER_DEBUG("  -> Active!");
                return true;
            }
            USER_DEBUG("  -> Expired (expiry <= now_ts)");
        }
        USER_DEBUG("has_subscription: no active subscriptions found");
        return false;
    }

    // Check specific level
    auto it = impl_->subscriptions.find(level);
    if (it == impl_->subscriptions.end()) {
        USER_DEBUG("has_subscription: level '" + level + "' not found");
        return false;
    }

    bool active = it->second.expiry == -1 || it->second.expiry > now_ts;
    USER_DEBUG("has_subscription: level '" + level + "' expiry=" + std::to_string(it->second.expiry) + " active=" + (active ? "true" : "false"));
    return active;
}

bool UserData::is_lifetime(const std::string& level) const {
    if (!impl_ || !impl_->valid) return false;

    auto it = impl_->subscriptions.find(level);
    if (it == impl_->subscriptions.end()) return false;

    return it->second.expiry == -1;
}

std::string UserData::get_subscription_name(const std::string& level) const {
    if (!impl_ || !impl_->valid) return "";

    auto it = impl_->subscriptions.find(level);
    if (it == impl_->subscriptions.end()) return "";

    return it->second.name;
}

int64_t UserData::get_subscription_expiry(const std::string& level) const {
    if (!impl_ || !impl_->valid) return 0;

    auto it = impl_->subscriptions.find(level);
    if (it == impl_->subscriptions.end()) return 0;

    return it->second.expiry;
}

int64_t UserData::get_subscription_time_left(const std::string& level) const {
    if (!impl_ || !impl_->valid) return 0;

    auto it = impl_->subscriptions.find(level);
    if (it == impl_->subscriptions.end()) return 0;

    if (it->second.expiry == -1) return -1;  // Lifetime

    auto now = std::chrono::system_clock::now();
    auto now_ts = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();

    int64_t diff = it->second.expiry - now_ts;
    return diff > 0 ? diff : 0;
}

std::string UserData::format_time_left(const std::string& level) const {
    if (!impl_ || !impl_->valid) return "";

    std::string target_level = level;

    // If no level specified, find first active one
    if (target_level.empty()) {
        auto levels = get_active_subscription_levels();
        if (levels.empty()) return "No active subscription";
        target_level = levels[0];
    }

    auto it = impl_->subscriptions.find(target_level);
    if (it == impl_->subscriptions.end()) return "Not found";

    if (it->second.expiry == -1) return "Lifetime";

    int64_t seconds = get_subscription_time_left(target_level);
    if (seconds <= 0) return "Expired";

    // Format time
    int64_t days = seconds / 86400;
    seconds %= 86400;
    int64_t hours = seconds / 3600;
    seconds %= 3600;
    int64_t minutes = seconds / 60;

    std::stringstream ss;

    if (days > 0) {
        ss << days << " day" << (days != 1 ? "s" : "");
        if (hours > 0) ss << ", " << hours << " hour" << (hours != 1 ? "s" : "");
    } else if (hours > 0) {
        ss << hours << " hour" << (hours != 1 ? "s" : "");
        if (minutes > 0) ss << ", " << minutes << " minute" << (minutes != 1 ? "s" : "");
    } else if (minutes > 0) {
        ss << minutes << " minute" << (minutes != 1 ? "s" : "");
    } else {
        ss << "Less than a minute";
    }

    return ss.str();
}

std::vector<std::string> UserData::get_active_subscription_levels() const {
    std::vector<std::string> result;
    if (!impl_ || !impl_->valid) return result;

    auto now = std::chrono::system_clock::now();
    auto now_ts = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();

    for (const auto& [level, sub] : impl_->subscriptions) {
        if (sub.expiry == -1 || sub.expiry > now_ts) {
            result.push_back(level);
        }
    }

    return result;
}

std::map<std::string, std::string> UserData::get_all_subscription_names() const {
    std::map<std::string, std::string> result;
    if (!impl_ || !impl_->valid) return result;

    for (const auto& [level, sub] : impl_->subscriptions) {
        result[level] = sub.name;
    }

    return result;
}

std::string UserData::get_variable(const std::string& name, const std::string& default_value) const {
    auto it = variables.find(name);
    if (it == variables.end()) return default_value;
    return it->second;
}

bool UserData::is_valid() const {
    return impl_ && impl_->valid;
}

const std::string& UserData::raw_json() const {
    static const std::string empty;
    if (!impl_) return empty;
    return impl_->raw_json;
}

} // namespace oliviauth
