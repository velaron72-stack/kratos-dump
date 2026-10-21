// Freestanding sample library used to build analysis fixtures for every supported architecture.
typedef unsigned long size_t_;
extern int puts(const char*);
extern size_t_ strlen(const char*);
extern void* memcpy(void*, const void*, size_t_);

static const char kGreeting[] = "KRATOS fixture greeting";
static const char kPath[] = "/data/data/com.kratos.sample/files";
const char* const kNames[] = {"alpha", "beta", "gamma"};

typedef int (*op_fn)(int, int);

__attribute__((noinline)) int kratos_add(int a, int b) { return a + b; }
__attribute__((noinline)) int kratos_mul(int a, int b) { return a * b; }
__attribute__((noinline)) static int kratos_hidden_sub(int a, int b) { return a - b; }

// Table of function pointers: found through relocations as a pointer table.
const op_fn kOps[] = {kratos_add, kratos_mul, kratos_hidden_sub, kratos_add};

__attribute__((noinline)) int kratos_dispatch(int idx, int a, int b) { return kOps[idx & 3](a, b); }

__attribute__((noinline)) int kratos_greet(void) {
  puts(kGreeting);
  return (int)strlen(kPath);
}

__attribute__((noinline)) void kratos_copy(char* dst, const char* src, int n) { memcpy(dst, src, (size_t_)n); }

int Java_com_kratos_sample_Native_nativeAdd(void* env, void* thiz, int a, int b) { return kratos_add(a, b); }
int Java_com_kratos_sample_Native_nativeName__ILjava_lang_String_2(void* env, void* thiz, int a, void* s) { return a + kratos_greet(); }
int JNI_OnLoad(void* vm, void* reserved) { return 0x10006; }

int g_counter = 5;
__attribute__((constructor)) static void kratos_init(void) { g_counter += 1; }

int kratos_names_len(void) {
  int n = 0;
  for (int i = 0; i < 3; i++) n += (int)strlen(kNames[i]);
  return n;
}
