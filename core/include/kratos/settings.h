// Setting registry (single source of truth for UI schema, validation and profiles) and Config store.
#pragma once

#include "kratos/common.h"
#include "kratos/json.h"

namespace kratos {

enum class SettingKind { Bool, Int, Number, Enum, String, Flags };

struct EnumOption {
  std::string value;
  std::string label;
};

struct SettingInfo {
  std::string purpose;      // what the parameter is for
  std::string effect;       // effect on the result
  std::string performance;  // speed / memory / file size
  std::string limits;       // restrictions
  std::string example;      // example of use
};

struct SettingDef {
  std::string key;
  std::string category;
  std::string title;
  SettingKind kind = SettingKind::Bool;
  Json def;
  double min = 0, max = 0;
  std::vector<EnumOption> options;
  std::string scope = "native";  // "native" (engine consumes it) or "ui" (Kotlin app consumes it)
  SettingInfo info;
  bool advanced = false;
};

struct CategoryDef {
  std::string id, title, description;
};

struct ProfileDef {
  std::string id, title, description;
  std::vector<std::pair<std::string, Json>> overrides;  // on top of the defaults ("standard")
};

const std::vector<CategoryDef>& setting_categories();
const std::vector<SettingDef>& all_settings();
const SettingDef* find_setting(const std::string& key);
const std::vector<ProfileDef>& builtin_profiles();
const ProfileDef* find_profile(const std::string& id);

// Full key->value map for a built-in profile.
Json profile_values(const std::string& profile_id);
Json defaults_json();
// UI schema: categories, settings with info texts, profiles with their full values.
Json schema_json();

struct ConfigIssue {
  std::string key;
  std::string message;
};

class Config {
 public:
  Config();  // defaults
  Config(const Config& o);
  Config& operator=(const Config& o);
  // Merges the given object over the defaults; unknown/invalid values are reported in issues and ignored/clamped.
  static Config from_json(const Json& obj, std::vector<ConfigIssue>* issues = nullptr);
  Json to_json() const;

  // Typed access. Unknown key throws std::logic_error (programming error). Every read is recorded.
  bool b(const std::string& key) const;
  i64 i(const std::string& key) const;
  double n(const std::string& key) const;
  std::string s(const std::string& key) const;
  std::vector<std::string> list(const std::string& key) const;  // flags or comma separated string
  bool flag(const std::string& key, const std::string& value) const;
  // "limits.*"-style integers: 0 means no user limit.
  u64 limit(const std::string& key) const;

  // Keys whose value differs from the given built-in profile.
  std::vector<std::string> diff_from(const std::string& profile_id) const;

  void set(const std::string& key, const Json& v);
  std::set<std::string> touched() const;
  void clear_touched() const;

 private:
  const Json& get(const std::string& key) const;
  std::map<std::string, Json> v_;
  mutable std::set<std::string> touched_;
  mutable std::mutex mu_;
};

}  // namespace kratos
