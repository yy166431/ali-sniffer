// fishhook.c  — minimal fishhook usable on iOS
// 原版见 https://github.com/facebook/fishhook
// 这里给的是足够 rebind 常见 C 符号的精简实现

#include "fishhook.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#if __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_COMMAND LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_COMMAND LC_SEGMENT
#endif

static void rebind_symbols_for_image(const struct mach_header *header,
                                     intptr_t slide,
                                     struct rebinding rebindings[],
                                     size_t rebindings_nel) {
  // 找 __LINKEDIT / __DATA / __DATA_CONST 段
  const struct mach_header *mh = header;
  struct load_command *lc = (struct load_command *)((uintptr_t)mh + sizeof(mach_header_t));
  segment_command_t *segLINKEDIT = NULL;
  segment_command_t *segDATA = NULL;
  struct symtab_command *symtab = NULL;
  struct dysymtab_command *dysymtab = NULL;

  for (uint32_t i = 0; i < mh->ncmds; i++, lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize)) {
    if (lc->cmd == LC_SEGMENT_COMMAND) {
      segment_command_t *seg = (segment_command_t *)lc;
      if (!strcmp(seg->segname, SEG_LINKEDIT)) segLINKEDIT = seg;
      else if (!strcmp(seg->segname, SEG_DATA) || !strcmp(seg->segname, "__DATA_CONST")) segDATA = seg;
    } else if (lc->cmd == LC_SYMTAB) {
      symtab = (struct symtab_command *)lc;
    } else if (lc->cmd == LC_DYSYMTAB) {
      dysymtab = (struct dysymtab_command *)lc;
    }
  }
  if (!segLINKEDIT || !segDATA || !symtab || !dysymtab) return;

  uintptr_t linkedit_base = (uintptr_t)slide + segLINKEDIT->vmaddr - segLINKEDIT->fileoff;
  nlist_t *symtab_entries = (nlist_t *)(linkedit_base + symtab->symoff);
  char *strtab = (char *)(linkedit_base + symtab->stroff);
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab->indirectsymoff);

  // 遍历 __DATA 段里的符号指针表
  lc = (struct load_command *)((uintptr_t)mh + sizeof(mach_header_t));
  for (uint32_t i = 0; i < mh->ncmds; i++, lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize)) {
    if (lc->cmd != LC_SEGMENT_COMMAND) continue;
    segment_command_t *seg = (segment_command_t *)lc;
    if (strcmp(seg->segname, SEG_DATA) && strcmp(seg->segname, "__DATA_CONST")) continue;

    struct section *sec = (struct section *)((uintptr_t)seg + sizeof(segment_command_t));
    for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
      uint32_t type = sec->flags & SECTION_TYPE;
      if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) continue;

      uint32_t *indirect = indirect_symtab + sec->reserved1;
      void **pointers = (void **)((uintptr_t)slide + sec->addr);
      for (uint32_t k = 0; k < sec->size / sizeof(void *); k++) {
        uint32_t sym_index = indirect[k];
        if (sym_index == INDIRECT_SYMBOL_ABS || sym_index == INDIRECT_SYMBOL_LOCAL) continue;

        nlist_t sym = symtab_entries[sym_index];
        const char *name = strtab + sym.n_un.n_strx;
        if (!name) continue;

        for (size_t r = 0; r < rebindings_nel; r++) {
          if (strcmp(name + 1, rebindings[r].name) == 0) { // 跳过前导下划线
            if (rebindings[r].replaced && *rebindings[r].replaced == NULL) {
              *rebindings[r].replaced = pointers[k];
            }
            pointers[k] = rebindings[r].replacement;
          }
        }
      }
    }
  }
}

static void _rebind(const struct mach_header *mh, intptr_t slide) {
  // 占位，实际在 rebind_symbols 里设置
}

static struct rebinding *g_rebindings;
static size_t g_rebindings_n;

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  g_rebindings = rebindings;
  g_rebindings_n = rebindings_nel;

  // 对当前已加载的所有 image 处理一次
  uint32_t count = _dyld_image_count();
  for (uint32_t i = 0; i < count; i++) {
    const struct mach_header *mh = _dyld_get_image_header(i);
    intptr_t slide = _dyld_get_image_vmaddr_slide(i);
    rebind_symbols_for_image(mh, slide, g_rebindings, g_rebindings_n);
  }

  // 并注册回调，对后续加载 image 也处理
  _dyld_register_func_for_add_image(rebind_symbols_for_image);
  return 0;
}
