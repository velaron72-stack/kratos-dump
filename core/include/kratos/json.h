// Minimal JSON value, parser and serializer (insertion-ordered objects).
#pragma once

#include "kratos/common.h"

namespace kratos {

class Json {
 public:
  enum Type { Null, Bool, Int, Double, String, Array, Object };

  Json() = default;
  Json(bool v) : t_(Bool), b_(v) {}
  Json(int v) : t_(Int), i_(v) {}
  Json(long v) : t_(Int), i_(v) {}
  Json(long long v) : t_(Int), i_(v) {}
  Json(unsigned v) : t_(Int), i_(v) {}
  Json(unsigned long v) { set_unsigned(v); }
  Json(unsigned long long v) { set_unsigned(v); }
  Json(double v) : t_(Double), d_(v) {}
  Json(const char* v) : t_(String), s_(v ? v : "") {}
  Json(const std::string& v) : t_(String), s_(v) {}

  static Json array() {
    Json j;
    j.t_ = Array;
    return j;
  }
  static Json object() {
    Json j;
    j.t_ = Object;
    return j;
  }

  Type type() const { return t_; }
  bool is_null() const { return t_ == Null; }
  bool is_bool() const { return t_ == Bool; }
  bool is_int() const { return t_ == Int; }
  bool is_number() const { return t_ == Int || t_ == Double; }
  bool is_string() const { return t_ == String; }
  bool is_array() const { return t_ == Array; }
  bool is_object() const { return t_ == Object; }

  bool as_bool(bool def = false) const { return t_ == Bool ? b_ : (t_ == Int ? i_ != 0 : def); }
  i64 as_int(i64 def = 0) const { return t_ == Int ? i_ : (t_ == Double ? (i64)d_ : def); }
  double as_double(double def = 0) const { return t_ == Double ? d_ : (t_ == Int ? (double)i_ : def); }
  const std::string& as_string() const { return s_; }
  std::string as_string_or(const std::string& def) const { return t_ == String ? s_ : def; }

  // Object access
  Json& set(const std::string& key, Json v);
  Json& operator[](const std::string& key);
  const Json* find(const std::string& key) const;
  bool has(const std::string& key) const { return find(key) != nullptr; }
  const std::vector<std::pair<std::string, Json>>& members() const { return members_; }
  bool erase(const std::string& key);

  // Array access
  Json& push(Json v);
  size_t size() const { return t_ == Array ? elems_.size() : members_.size(); }
  const std::vector<Json>& elems() const { return elems_; }
  std::vector<Json>& elems() { return elems_; }
  const Json& at(size_t i) const { return elems_.at(i); }

  std::string dump(int indent = -1) const;
  static bool parse(const std::string& text, Json& out, std::string& err);

 private:
  void set_unsigned(unsigned long long v) {
    if (v <= (unsigned long long)INT64_MAX) {
      t_ = Int;
      i_ = (i64)v;
    } else {
      t_ = Double;
      d_ = (double)v;
    }
  }
  void dump_to(std::string& out, int indent, int depth) const;

  Type t_ = Null;
  bool b_ = false;
  i64 i_ = 0;
  double d_ = 0;
  std::string s_;
  std::vector<Json> elems_;
  std::vector<std::pair<std::string, Json>> members_;
};

// Escapes arbitrary bytes into a valid JSON string body (invalid UTF-8 -> U+FFFD).
std::string json_escape(const std::string& s);

}  // namespace kratos
