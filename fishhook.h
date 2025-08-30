// fishhook.h  — from Facebook fishhook (trimmed interface)

#ifndef fishhook_h
#define fishhook_h

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rebinding {
  const char *name;     // 要替换的符号名
  void *replacement;    // 我们的实现
  void **replaced;      // 保存原实现的指针地址
};

// 重新绑定一组符号
int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

#ifdef __cplusplus
}
#endif

#endif /* fishhook_h */
