// Flat C interface of the KRATOS DUMP core. Every function takes and returns plain C types; structured data travels as JSON text.
// Returned strings are allocated by the library and must be released with kratos_free(). No function throws.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Both callbacks are invoked from engine worker threads, possibly several at the same time. They must be thread-safe and must not block.
typedef void (*kratos_progress_fn)(void* user, const char* stage, unsigned long long done, unsigned long long total, const char* text);
// level: 0 debug, 1 info, 2 ok, 3 warning, 4 error
typedef void (*kratos_log_fn)(void* user, unsigned long long ts_ms, int level, const char* stage, const char* msg);

// {"version", "dependencies": {...}, "arch": [...]}
char* kratos_info_json(void);
// Settings registry: categories, settings with ⓘ texts, profiles with their full values.
char* kratos_schema_json(void);
// {"issues":[{"key","message"}], "values":{...all keys...}, "changed":[keys that differ from the profile]}
char* kratos_validate_config_json(const char* profile_id, const char* overrides_json);

// Content checks before a run. The descriptor is only read (it is duplicated internally) and stays open.
char* kratos_probe_apk_json(int fd, const char* name, const char* profile_id, const char* overrides_json, const char* temp_dir);
char* kratos_probe_lib_json(int fd, const char* name);
char* kratos_probe_meta_json(int fd, const char* name);
// {"exists","is_dir","writable","error","free_bytes","free_known"}
char* kratos_check_dir_json(const char* path);

// One run at a time per handle. cancel() may be called from any thread.
void* kratos_run_new(void);
void kratos_run_cancel(void* handle);
void kratos_run_delete(void* handle);
// request_json: {"mode":"apk|lib","display_name","lib_name","meta_name","out_root","temp_dir","profile","selected_libs":[],
//                "selected_meta","config":{overrides}}. The descriptors are owned by the caller and are not closed here.
// Returns the outcome: {"status_id","status_text","run_dir","summary_path","error","summary":{...}}.
char* kratos_run_json(void* handle, const char* request_json, int apk_fd, int lib_fd, int meta_fd, kratos_progress_fn progress, kratos_log_fn log, void* user);

void kratos_free(char* p);

#ifdef __cplusplus
}
#endif
