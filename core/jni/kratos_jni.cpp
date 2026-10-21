// JNI bridge: com.kratos.dump.Native -> flat C interface (kratos/api.h).
// Strings cross the boundary as UTF-16 (NewString/GetStringChars) so that arbitrary file names and log text never trip
// the modified-UTF-8 rules of NewStringUTF.
#include <jni.h>

#include <atomic>
#include <string>

#include "kratos/api.h"

namespace {

JavaVM* g_vm = nullptr;

// Threads created by the engine are attached on first use and detached when the thread exits.
struct Attached {
  bool did_attach = false;
  ~Attached() {
    if (did_attach && g_vm) g_vm->DetachCurrentThread();
  }
};

JNIEnv* env_for_thread() {
  if (!g_vm) return nullptr;
  JNIEnv* env = nullptr;
  jint r = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
  if (r == JNI_OK) return env;
  if (r != JNI_EDETACHED) return nullptr;
  thread_local Attached guard;
#ifdef __ANDROID__
  if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return nullptr;
#else
  if (g_vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) != JNI_OK) return nullptr;
#endif
  guard.did_attach = true;
  return env;
}

// UTF-8 -> UTF-16; invalid sequences become U+FFFD.
std::u16string utf8_to_utf16(const char* s) {
  std::u16string out;
  if (!s) return out;
  const unsigned char* p = reinterpret_cast<const unsigned char*>(s);
  while (*p) {
    uint32_t cp = 0xFFFD;
    size_t len = 1;
    unsigned char c = *p;
    if (c < 0x80) {
      cp = c;
    } else if (c >= 0xC2 && c < 0xE0 && (p[1] & 0xC0) == 0x80) {
      cp = ((c & 0x1Fu) << 6) | (p[1] & 0x3Fu);
      len = 2;
    } else if (c >= 0xE0 && c < 0xF0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
      uint32_t v = ((c & 0x0Fu) << 12) | ((p[1] & 0x3Fu) << 6) | (p[2] & 0x3Fu);
      if (v >= 0x800 && !(v >= 0xD800 && v <= 0xDFFF)) {
        cp = v;
        len = 3;
      }
    } else if (c >= 0xF0 && c < 0xF5 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
      uint32_t v = ((c & 0x07u) << 18) | ((p[1] & 0x3Fu) << 12) | ((p[2] & 0x3Fu) << 6) | (p[3] & 0x3Fu);
      if (v >= 0x10000 && v <= 0x10FFFF) {
        cp = v;
        len = 4;
      }
    }
    if (cp >= 0x10000) {
      cp -= 0x10000;
      out.push_back(static_cast<char16_t>(0xD800 + (cp >> 10)));
      out.push_back(static_cast<char16_t>(0xDC00 + (cp & 0x3FF)));
    } else {
      out.push_back(static_cast<char16_t>(cp));
    }
    p += len;
  }
  return out;
}

jstring to_jstring(JNIEnv* env, const char* utf8) {
  std::u16string u = utf8_to_utf16(utf8);
  return env->NewString(reinterpret_cast<const jchar*>(u.data()), static_cast<jsize>(u.size()));
}

std::string from_jstring(JNIEnv* env, jstring js) {
  std::string out;
  if (!js) return out;
  const jchar* chars = env->GetStringChars(js, nullptr);
  if (!chars) return out;
  jsize n = env->GetStringLength(js);
  for (jsize i = 0; i < n; i++) {
    uint32_t cp = chars[i];
    if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < n && chars[i + 1] >= 0xDC00 && chars[i + 1] <= 0xDFFF) {
      cp = 0x10000 + ((cp - 0xD800) << 10) + (chars[i + 1] - 0xDC00u);
      i++;
    } else if (cp >= 0xD800 && cp <= 0xDFFF) {
      cp = 0xFFFD;
    }
    if (cp < 0x80) out.push_back(static_cast<char>(cp));
    else if (cp < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }
  env->ReleaseStringChars(js, chars);
  return out;
}

// Takes ownership of a library-allocated string and returns it as a Java string.
jstring take_result(JNIEnv* env, char* s) {
  if (!s) return to_jstring(env, "{\"ok\":false,\"error\":\"out of memory\"}");
  jstring r = to_jstring(env, s);
  kratos_free(s);
  return r;
}

struct ListenerCtx {
  jobject listener = nullptr;  // global reference
  jmethodID on_progress = nullptr;
  jmethodID on_log = nullptr;
};

void progress_trampoline(void* user, const char* stage, unsigned long long done, unsigned long long total, const char* text) {
  auto* c = static_cast<ListenerCtx*>(user);
  JNIEnv* env = env_for_thread();
  if (!c || !env || !c->listener) return;
  jstring js = to_jstring(env, stage);
  jstring jt = to_jstring(env, text);
  env->CallVoidMethod(c->listener, c->on_progress, js, static_cast<jlong>(done), static_cast<jlong>(total), jt);
  if (env->ExceptionCheck()) env->ExceptionClear();
  env->DeleteLocalRef(js);
  env->DeleteLocalRef(jt);
}

void log_trampoline(void* user, unsigned long long ts_ms, int level, const char* stage, const char* msg) {
  auto* c = static_cast<ListenerCtx*>(user);
  JNIEnv* env = env_for_thread();
  if (!c || !env || !c->listener) return;
  jstring js = to_jstring(env, stage);
  jstring jm = to_jstring(env, msg);
  env->CallVoidMethod(c->listener, c->on_log, static_cast<jlong>(ts_ms), static_cast<jint>(level), js, jm);
  if (env->ExceptionCheck()) env->ExceptionClear();
  env->DeleteLocalRef(js);
  env->DeleteLocalRef(jm);
}

}  // namespace

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  g_vm = vm;
  return JNI_VERSION_1_6;
}

JNIEXPORT jstring JNICALL Java_com_kratos_dump_Native_info(JNIEnv* env, jclass) { return take_result(env, kratos_info_json()); }

JNIEXPORT jstring JNICALL Java_com_kratos_dump_Native_schema(JNIEnv* env, jclass) { return take_result(env, kratos_schema_json()); }

JNIEXPORT jstring JNICALL Java_com_kratos_dump_Native_validateConfig(JNIEnv* env, jclass, jstring profile, jstring overrides) {
  return take_result(env, kratos_validate_config_json(from_jstring(env, profile).c_str(), from_jstring(env, overrides).c_str()));
}

JNIEXPORT jstring JNICALL Java_com_kratos_dump_Native_probeApk(JNIEnv* env, jclass, jint fd, jstring name, jstring profile, jstring overrides, jstring temp) {
  return take_result(env, kratos_probe_apk_json(fd, from_jstring(env, name).c_str(), from_jstring(env, profile).c_str(), from_jstring(env, overrides).c_str(),
                                                from_jstring(env, temp).c_str()));
}

JNIEXPORT jstring JNICALL Java_com_kratos_dump_Native_probeLib(JNIEnv* env, jclass, jint fd, jstring name) {
  return take_result(env, kratos_probe_lib_json(fd, from_jstring(env, name).c_str()));
}

JNIEXPORT jstring JNICALL Java_com_kratos_dump_Native_probeMeta(JNIEnv* env, jclass, jint fd, jstring name) {
  return take_result(env, kratos_probe_meta_json(fd, from_jstring(env, name).c_str()));
}

JNIEXPORT jstring JNICALL Java_com_kratos_dump_Native_checkDir(JNIEnv* env, jclass, jstring path) {
  return take_result(env, kratos_check_dir_json(from_jstring(env, path).c_str()));
}

JNIEXPORT jlong JNICALL Java_com_kratos_dump_Native_runNew(JNIEnv*, jclass) { return reinterpret_cast<jlong>(kratos_run_new()); }

JNIEXPORT void JNICALL Java_com_kratos_dump_Native_runCancel(JNIEnv*, jclass, jlong h) { kratos_run_cancel(reinterpret_cast<void*>(h)); }

JNIEXPORT void JNICALL Java_com_kratos_dump_Native_runDelete(JNIEnv*, jclass, jlong h) { kratos_run_delete(reinterpret_cast<void*>(h)); }

JNIEXPORT jstring JNICALL Java_com_kratos_dump_Native_run(JNIEnv* env, jclass, jlong h, jstring request, jint apk_fd, jint lib_fd, jint meta_fd, jobject listener) {
  ListenerCtx ctx;
  if (listener) {
    jclass cls = env->GetObjectClass(listener);
    ctx.on_progress = env->GetMethodID(cls, "onProgress", "(Ljava/lang/String;JJLjava/lang/String;)V");
    ctx.on_log = env->GetMethodID(cls, "onLog", "(JILjava/lang/String;Ljava/lang/String;)V");
    env->DeleteLocalRef(cls);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (ctx.on_progress && ctx.on_log) ctx.listener = env->NewGlobalRef(listener);
  }
  std::string req = from_jstring(env, request);
  char* res = kratos_run_json(reinterpret_cast<void*>(h), req.c_str(), apk_fd, lib_fd, meta_fd, ctx.listener ? progress_trampoline : nullptr,
                              ctx.listener ? log_trampoline : nullptr, &ctx);
  if (ctx.listener) env->DeleteGlobalRef(ctx.listener);
  return take_result(env, res);
}

}  // extern "C"
