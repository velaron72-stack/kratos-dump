// Second translation unit: built in the opposite ARM instruction set (ARM32 only) to produce mixed ARM/Thumb code.
extern int kratos_add(int a, int b);
__attribute__((noinline)) int kratos_other_mode(int x) { return kratos_add(x, 7) * 3; }
