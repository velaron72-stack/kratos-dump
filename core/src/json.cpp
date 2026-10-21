#include "kratos/json.h"

#include <cmath>

namespace kratos {

Json& Json::set(const std::string& key, Json v) {
  if (t_ != Object) {
    t_ = Object;
    members_.clear();
  }
  for (auto& m : members_) {
    if (m.first == key) {
      m.second = std::move(v);
      return m.second;
    }
  }
  members_.emplace_back(key, std::move(v));
  return members_.back().second;
}

Json& Json::operator[](const std::string& key) {
  if (t_ != Object) {
    t_ = Object;
    members_.clear();
  }
  for (auto& m : members_)
    if (m.first == key) return m.second;
  members_.emplace_back(key, Json());
  return members_.back().second;
}

const Json* Json::find(const std::string& key) const {
  if (t_ != Object) return nullptr;
  for (auto& m : members_)
    if (m.first == key) return &m.second;
  return nullptr;
}

bool Json::erase(const std::string& key) {
  for (size_t i = 0; i < members_.size(); i++) {
    if (members_[i].first == key) {
      members_.erase(members_.begin() + (long)i);
      return true;
    }
  }
  return false;
}

Json& Json::push(Json v) {
  if (t_ != Array) {
    t_ = Array;
    elems_.clear();
  }
  elems_.push_back(std::move(v));
  return elems_.back();
}

static int utf8_seq_len(const unsigned char* p, size_t n) {
  unsigned char c = p[0];
  if (c < 0x80) return 1;
  if (c >= 0xC2 && c <= 0xDF) return (n >= 2 && (p[1] & 0xC0) == 0x80) ? 2 : 0;
  if (c >= 0xE0 && c <= 0xEF) {
    if (n < 3 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80) return 0;
    if (c == 0xE0 && p[1] < 0xA0) return 0;
    if (c == 0xED && p[1] >= 0xA0) return 0;
    return 3;
  }
  if (c >= 0xF0 && c <= 0xF4) {
    if (n < 4 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 || (p[3] & 0xC0) != 0x80) return 0;
    if (c == 0xF0 && p[1] < 0x90) return 0;
    if (c == 0xF4 && p[1] >= 0x90) return 0;
    return 4;
  }
  return 0;
}

std::string json_escape(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 8);
  const unsigned char* p = (const unsigned char*)s.data();
  size_t n = s.size(), i = 0;
  while (i < n) {
    unsigned char c = p[i];
    if (c == '"') { o += "\\\""; i++; }
    else if (c == '\\') { o += "\\\\"; i++; }
    else if (c == '\n') { o += "\\n"; i++; }
    else if (c == '\r') { o += "\\r"; i++; }
    else if (c == '\t') { o += "\\t"; i++; }
    else if (c == '\b') { o += "\\b"; i++; }
    else if (c == '\f') { o += "\\f"; i++; }
    else if (c < 0x20 || c == 0x7F) { o += strf("\\u%04x", c); i++; }
    else if (c < 0x80) { o.push_back((char)c); i++; }
    else {
      int l = utf8_seq_len(p + i, n - i);
      if (l == 0) {
        o += "\\ufffd";
        i++;
      } else {
        o.append((const char*)p + i, (size_t)l);
        i += (size_t)l;
      }
    }
  }
  return o;
}

void Json::dump_to(std::string& out, int indent, int depth) const {
  auto nl = [&](int d) {
    if (indent < 0) return;
    out.push_back('\n');
    out.append((size_t)(indent * d), ' ');
  };
  switch (t_) {
    case Null: out += "null"; break;
    case Bool: out += b_ ? "true" : "false"; break;
    case Int: out += strf("%lld", (long long)i_); break;
    case Double:
      if (std::isfinite(d_)) {
        std::string s = strf("%.17g", d_);
        out += s;
      } else {
        out += "null";
      }
      break;
    case String:
      out.push_back('"');
      out += json_escape(s_);
      out.push_back('"');
      break;
    case Array:
      if (elems_.empty()) { out += "[]"; break; }
      out.push_back('[');
      for (size_t i = 0; i < elems_.size(); i++) {
        if (i) out.push_back(',');
        nl(depth + 1);
        elems_[i].dump_to(out, indent, depth + 1);
      }
      nl(depth);
      out.push_back(']');
      break;
    case Object:
      if (members_.empty()) { out += "{}"; break; }
      out.push_back('{');
      for (size_t i = 0; i < members_.size(); i++) {
        if (i) out.push_back(',');
        nl(depth + 1);
        out.push_back('"');
        out += json_escape(members_[i].first);
        out += indent < 0 ? "\":" : "\": ";
        members_[i].second.dump_to(out, indent, depth + 1);
      }
      nl(depth);
      out.push_back('}');
      break;
  }
}

std::string Json::dump(int indent) const {
  std::string s;
  dump_to(s, indent, 0);
  return s;
}

namespace {
struct Parser {
  const std::string& s;
  size_t i = 0;
  std::string err;
  explicit Parser(const std::string& str) : s(str) {}

  void ws() {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++;
  }
  bool fail(const char* m) {
    if (err.empty()) err = strf("%s at offset %zu", m, i);
    return false;
  }
  static void put_utf8(std::string& o, unsigned cp) {
    if (cp < 0x80) o.push_back((char)cp);
    else if (cp < 0x800) { o.push_back((char)(0xC0 | (cp >> 6))); o.push_back((char)(0x80 | (cp & 0x3F))); }
    else if (cp < 0x10000) {
      o.push_back((char)(0xE0 | (cp >> 12)));
      o.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
      o.push_back((char)(0x80 | (cp & 0x3F)));
    } else {
      o.push_back((char)(0xF0 | (cp >> 18)));
      o.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
      o.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
      o.push_back((char)(0x80 | (cp & 0x3F)));
    }
  }
  bool hex4(unsigned& v) {
    if (i + 4 > s.size()) return false;
    v = 0;
    for (int k = 0; k < 4; k++) {
      char c = s[i++];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
      else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
      else return false;
    }
    return true;
  }
  bool str(std::string& o) {
    if (i >= s.size() || s[i] != '"') return fail("expected string");
    i++;
    while (i < s.size()) {
      char c = s[i++];
      if (c == '"') return true;
      if (c == '\\') {
        if (i >= s.size()) return fail("bad escape");
        char e = s[i++];
        switch (e) {
          case '"': o.push_back('"'); break;
          case '\\': o.push_back('\\'); break;
          case '/': o.push_back('/'); break;
          case 'b': o.push_back('\b'); break;
          case 'f': o.push_back('\f'); break;
          case 'n': o.push_back('\n'); break;
          case 'r': o.push_back('\r'); break;
          case 't': o.push_back('\t'); break;
          case 'u': {
            unsigned cp;
            if (!hex4(cp)) return fail("bad \\u escape");
            if (cp >= 0xD800 && cp <= 0xDBFF) {
              unsigned lo;
              if (i + 2 <= s.size() && s[i] == '\\' && s[i + 1] == 'u') {
                i += 2;
                if (!hex4(lo)) return fail("bad \\u escape");
                if (lo >= 0xDC00 && lo <= 0xDFFF) cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                else cp = 0xFFFD;
              } else cp = 0xFFFD;
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) cp = 0xFFFD;
            put_utf8(o, cp);
            break;
          }
          default: return fail("bad escape");
        }
      } else {
        o.push_back(c);
      }
    }
    return fail("unterminated string");
  }
  bool value(Json& out, int depth) {
    if (depth > 64) return fail("nesting too deep");
    ws();
    if (i >= s.size()) return fail("unexpected end");
    char c = s[i];
    if (c == '{') {
      i++;
      out = Json::object();
      ws();
      if (i < s.size() && s[i] == '}') { i++; return true; }
      for (;;) {
        ws();
        std::string k;
        if (!str(k)) return false;
        ws();
        if (i >= s.size() || s[i] != ':') return fail("expected ':'");
        i++;
        Json v;
        if (!value(v, depth + 1)) return false;
        out.set(k, std::move(v));
        ws();
        if (i < s.size() && s[i] == ',') { i++; continue; }
        if (i < s.size() && s[i] == '}') { i++; return true; }
        return fail("expected ',' or '}'");
      }
    }
    if (c == '[') {
      i++;
      out = Json::array();
      ws();
      if (i < s.size() && s[i] == ']') { i++; return true; }
      for (;;) {
        Json v;
        if (!value(v, depth + 1)) return false;
        out.push(std::move(v));
        ws();
        if (i < s.size() && s[i] == ',') { i++; continue; }
        if (i < s.size() && s[i] == ']') { i++; return true; }
        return fail("expected ',' or ']'");
      }
    }
    if (c == '"') {
      std::string v;
      if (!str(v)) return false;
      out = Json(v);
      return true;
    }
    if (s.compare(i, 4, "true") == 0) { i += 4; out = Json(true); return true; }
    if (s.compare(i, 5, "false") == 0) { i += 5; out = Json(false); return true; }
    if (s.compare(i, 4, "null") == 0) { i += 4; out = Json(); return true; }
    if (c == '-' || (c >= '0' && c <= '9')) {
      size_t st = i;
      bool isf = false;
      if (s[i] == '-') i++;
      while (i < s.size() && isdigit((unsigned char)s[i])) i++;
      if (i < s.size() && s[i] == '.') { isf = true; i++; while (i < s.size() && isdigit((unsigned char)s[i])) i++; }
      if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        isf = true;
        i++;
        if (i < s.size() && (s[i] == '+' || s[i] == '-')) i++;
        while (i < s.size() && isdigit((unsigned char)s[i])) i++;
      }
      std::string num = s.substr(st, i - st);
      if (num.empty() || num == "-") return fail("bad number");
      if (!isf) {
        errno = 0;
        long long v = strtoll(num.c_str(), nullptr, 10);
        if (errno == 0) { out = Json((long long)v); return true; }
      }
      out = Json(strtod(num.c_str(), nullptr));
      return true;
    }
    return fail("unexpected character");
  }
};
}  // namespace

bool Json::parse(const std::string& text, Json& out, std::string& err) {
  Parser p(text);
  Json v;
  if (!p.value(v, 0)) {
    err = p.err;
    return false;
  }
  p.ws();
  if (p.i != text.size()) {
    err = strf("trailing data at offset %zu", p.i);
    return false;
  }
  out = std::move(v);
  return true;
}

}  // namespace kratos
