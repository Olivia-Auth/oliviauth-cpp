/**
 * @file json_utils.h
 * @brief JSON utilities with null-safe value extraction
 *
 * This header provides a wrapper around nlohmann::json that handles null values
 * gracefully, returning default values instead of throwing exceptions.
 */

#pragma once

#ifdef OLIVIAUTH_USE_EXTERNAL_JSON
    #include <nlohmann/json.hpp>
#else
    #include "../deps/json.hpp"
#endif

namespace oliviauth {

/**
 * @brief Wrapper around nlohmann::json with null-safe value extraction
 *
 * Usage:
 *   json j = json::parse(data);
 *   SafeJson safe(j);
 *   std::string name = safe.get<std::string>("name");  // Returns "" if null
 *   int64_t count = safe.get<int64_t>("count", -1);    // Returns -1 if null
 */
class SafeJson {
public:
    using json = nlohmann::json;

    SafeJson(const json& j) : data_(j) {}
    SafeJson(json&& j) : data_(std::move(j)) {}

    /**
     * @brief Null-safe value extraction with type inference
     * @param key The JSON key to look up
     * @param default_val Default value if key is missing or null
     * @return The value or default
     */
    template<typename T>
    T get(const std::string& key, const T& default_val = T{}) const {
        if (!data_.contains(key) || data_[key].is_null()) {
            return default_val;
        }
        try {
            return data_[key].get<T>();
        } catch (...) {
            return default_val;
        }
    }

    /**
     * @brief Special handling for strings - converts non-strings to string
     */
    std::string get_string(const std::string& key, const std::string& default_val = "") const {
        if (!data_.contains(key) || data_[key].is_null()) {
            return default_val;
        }
        if (data_[key].is_string()) {
            return data_[key].get<std::string>();
        }
        return data_[key].dump();
    }

    // Forward other operations to underlying json
    bool contains(const std::string& key) const { return data_.contains(key); }
    bool is_null() const { return data_.is_null(); }
    bool is_object() const { return data_.is_object(); }
    bool is_array() const { return data_.is_array(); }
    bool is_string() const { return data_.is_string(); }
    bool is_number() const { return data_.is_number(); }

    const json& operator[](const std::string& key) const { return data_[key]; }
    const json& underlying() const { return data_; }

    auto items() const { return data_.items(); }
    auto begin() const { return data_.begin(); }
    auto end() const { return data_.end(); }
    size_t size() const { return data_.size(); }

private:
    json data_;
};

/**
 * @brief Free function for null-safe value extraction (can be used without wrapper)
 */
template<typename T>
inline T json_value(const nlohmann::json& j, const std::string& key, const T& default_val = T{}) {
    if (!j.contains(key) || j[key].is_null()) {
        return default_val;
    }
    try {
        return j[key].get<T>();
    } catch (...) {
        return default_val;
    }
}

/**
 * @brief Specialization for strings
 */
template<>
inline std::string json_value<std::string>(const nlohmann::json& j, const std::string& key, const std::string& default_val) {
    if (!j.contains(key) || j[key].is_null()) {
        return default_val;
    }
    if (j[key].is_string()) {
        return j[key].get<std::string>();
    }
    return j[key].dump();
}

} // namespace oliviauth
