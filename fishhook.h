// fishhook.h — Copyright (c) Facebook, Inc.
// 许可: MIT. 仅接口。

#ifndef fishhook_h
#define fishhook_h

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rebinding {
  const char *name;     // 需要替换的符号名（去掉前导下划线）
  void *replacement;    // 我们的实现
  void **replaced;      // 用来保存原实现指针的地址
};

// 绑定一组符号（对当前和后续加载的 image 都生效）
int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

#ifdef __cplusplus
}
#endif

#endif /* fishhook_h */
