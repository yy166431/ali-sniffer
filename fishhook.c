// fishhook.c — Facebook MIT license（常用实现）

#include "fishhook.h"
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#if defined(__LP64__)
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
  struct rebindings_entry *new_entry = (struct rebindings_entry *)malloc(sizeof(struct rebindings_entry));
  if (!new_entry) return -1;
  new_entry->rebindings = (struct rebinding *)malloc(sizeof(struct rebinding) * nel);
  if (!new_entry->rebindings) { free(new_entry); return -1; }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
  new_entry->rebindings_nel = nel;
  new_entry->next = *rebindings_head;
  *rebindings_head = new_entry;
  return 0;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);

  for (uint i = 0; i < section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL) continue;

    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    if (!symbol_name) continue;

    struct rebindings_entry *cur = rebindings;
    while (cur) {
      for (uint j = 0; j < cur->rebindings_nel; j++) {
        if (symbol_name[0] == '_' && strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
          if (cur->rebindings[j].replaced && *cur->rebindings[j].replaced == NULL) {
            *cur->rebindings[j].replaced = indirect_symbol_bindings[i];
          }
          indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
          goto symbol_bound;
        }
      }
      cur = cur->next;
    }
  symbol_bound:;
  }
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
  Dl_info info;
  if (dladdr(header, &info) == 0) return;

  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  segment_command_t *data_segment = NULL;
  segment_command_t *data_const_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += ((struct load_command *)cur)->cmdsize) {
    struct load_command *lc = (struct load_command *)cur;
    switch (lc->cmd) {
      case LC_SEGMENT_ARCH_DEPENDENT:
        cur_seg_cmd = (segment_command_t *)cur;
        if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) linkedit_segment = cur_seg_cmd;
        else if (strcmp(cur_seg_cmd->segname, SEG_DATA) == 0) data_segment = cur_seg_cmd;
        else if (strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) == 0) data_const_segment = cur_seg_cmd;
        break;
      case LC_SYMTAB:
        symtab_cmd = (struct symtab_command*)lc; break;
      case LC_DYSYMTAB:
        dysymtab_cmd = (struct dysymtab_command*)lc; break;
      default: break;
    }
  }
  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment) return;

  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  if (data_segment) {
    section_t *sect = (section_t *)((uintptr_t)data_segment + sizeof(segment_command_t));
    for (uint i = 0; i < data_segment->nsects; i++, sect++) {
      uint32_t type = sect->flags & SECTION_TYPE;
      if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS) {
        perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
      }
    }
  }
  if (data_const_segment) {
    section_t *sect = (section_t *)((uintptr_t)data_const_segment + sizeof(segment_command_t));
    for (uint i = 0; i < data_const_segment->nsects; i++, sect++) {
      uint32_t type = sect->flags & SECTION_TYPE;
      if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS) {
        perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
      }
    }
  }
}

static void _rebind_symbols_for_image(const struct mach_header *header, intptr_t slide) {
  rebind_symbols_for_image(_rebindings_head, header, slide);
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
  if (retval < 0) return retval;

  if (!_dyld_get_image_header(0)) return retval;

  // 对已加载镜像处理
  uint32_t c = _dyld_image_count();
  for (uint i = 0; i < c; i++) {
    rebind_symbols_for_image(_rebindings_head, _dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
  }

  // 注册回调处理后续镜像
  _dyld_register_func_for_add_image(_rebind_symbols_for_image);
  return retval;
}
