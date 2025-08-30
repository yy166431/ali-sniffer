// fishhook.c
// https://github.com/facebook/fishhook

#include "fishhook.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#if defined(__LP64__)
typedef struct mach_header_64 mach_header_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#define segment_command_t segment_command_64
#else
typedef struct mach_header mach_header_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#define segment_command_t segment_command
#endif

static int _rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel, const mach_header_t *header);

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  for (uint32_t i = 0; i < _dyld_image_count(); i++) {
    _rebind_symbols(rebindings, rebindings_nel, _dyld_get_image_header(i));
  }
  return 0;
}

static int _rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel, const mach_header_t *header) {
  uintptr_t slide = _dyld_get_image_vmaddr_slide(0);
  struct load_command *cmd = (struct load_command *)((uintptr_t)header + sizeof(mach_header_t));
  for (uint32_t i = 0; i < header->ncmds; i++, cmd = (struct load_command *)((uintptr_t)cmd + cmd->cmdsize)) {
    if (cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      struct segment_command_t *seg = (struct segment_command_t *)cmd;
      if (strcmp(seg->segname, "__DATA") != 0 && strcmp(seg->segname, "__DATA_CONST") != 0) {
        continue;
      }
      struct section *sec = (struct section *)((uintptr_t)seg + sizeof(struct segment_command_t));
      for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
        if ((sec->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
            (sec->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
          uintptr_t *indirect_symbol_bindings = (uintptr_t *)(slide + sec->addr);
          for (uint32_t k = 0; k < sec->size / sizeof(void *); k++) {
            uintptr_t *cur = &indirect_symbol_bindings[k];
            for (size_t l = 0; l < rebindings_nel; l++) {
              if (*cur == (uintptr_t)rebindings[l].replaced) {
                *cur = (uintptr_t)rebindings[l].replacement;
              }
            }
          }
        }
      }
    }
  }
  return 0;
}
