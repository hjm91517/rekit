// Symbol interposition engine: classic fishhook sections + dyld chained fixups.
// No third-party code. Pointer math kept in C for predictability.

#import "REKInterpose.h"

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#import <objc/runtime.h>

#define REK_LC_DYLD_CHAINED_FIXUPS 0x80000034u
#define REK_LC_DYLD_EXPORTS_TRIE   0x80000033u

// ---- locally declared chained-fixups structs (avoids SDK version gating) ----
struct rek_fixups_header {
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;
    uint32_t symbols_format;
};

struct rek_starts_in_image {
    uint32_t seg_count;
    uint32_t seg_info_offset[1];
};

struct rek_starts_in_segment {
    uint32_t size;
    uint16_t page_size;
    uint16_t pointer_format;
    uint64_t segment_offset;
    uint32_t max_valid_pointer;
    uint16_t page_count;
    uint16_t page_start[1];
};

enum {
    REK_FMT_ARM64E = 1,
    REK_FMT_64 = 2,
    REK_FMT_32 = 3,
    REK_FMT_64_OFFSET = 6,
    REK_FMT_ARM64E_USERLAND = 9,
    REK_FMT_ARM64E_USERLAND24 = 12,
};

struct rek_ptr64_bind { uint64_t ordinal:24, addend:8, reserved:19, next:12, bind:1; };
struct rek_ptr64_plain { uint64_t target:36, high8:8, reserved:7, next:12, bind:1; };
struct rek_ptrarm64e_bind { uint64_t ordinal:16, zero:16, addend:19, next:11, bind:1; };
struct rek_ptrarm64e_plain { uint64_t target:43, diversity:16, addrDiv:1, key:2, next:11, bind:1; };

static int g_rebound = 0;
static int g_images = 0;
static int g_skipped = 0;
static int g_chained_images = 0;

int rek_chained_fixup_image_count(void) { return g_chained_images; }
int rek_last_image_count(void) { return g_images; }
int rek_last_skipped_count(void) { return g_skipped; }

static const struct mach_header_64 *rek_hdr(uint32_t idx) {
    const struct mach_header *raw = _dyld_get_image_header(idx);
    if (!raw) return NULL;
    if (raw->magic != MH_MAGIC_64 && raw->magic != MH_CIGAM_64) return NULL;
    return (const struct mach_header_64 *)raw;
}

int rek_main_has_chained_fixups(void) {
    const struct mach_header_64 *h = rek_hdr(0);
    if (!h) return 0;
    const uint8_t *p = (const uint8_t *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == REK_LC_DYLD_CHAINED_FIXUPS) return 1;
        p += lc->cmdsize;
    }
    return 0;
}

static int rek_page_write(void *addr, size_t len) {
    vm_size_t ps = 0;
    if (host_page_size(mach_host_self(), &ps) != KERN_SUCCESS || ps == 0) ps = 16384;
    uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    uintptr_t end = ((uintptr_t)addr + len + ps - 1) & ~(uintptr_t)(ps - 1);
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)start,
                                  (vm_size_t)(end - start), false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    return kr == KERN_SUCCESS;
}

static int rek_name_matches(const char *candidate, const char *wanted) {
    if (!candidate || !wanted) return 0;
    size_t n = strlen(wanted);
    if (strncmp(candidate, wanted, n) != 0) return 0;
    char tail = candidate[n];
    return tail == '\0' || tail == '$'; // tolerate "_$s" style decorations
}

/// Collect bind names for one image from its chained imports table.
static int rek_walk_chained(const struct mach_header_64 *h, intptr_t slide,
                            REKRebinding *rebs, size_t n) {
    const uint8_t *base = (const uint8_t *)h;
    const struct load_command *fixlc = NULL;
    const struct load_command *symlc = NULL;
    const uint8_t *p = (const uint8_t *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < 8) { g_skipped++; return 0; }
        if (lc->cmd == REK_LC_DYLD_CHAINED_FIXUPS) fixlc = lc;
        if (lc->cmd == LC_SYMTAB) symlc = lc;
        p += lc->cmdsize;
    }
    if (!fixlc) return -1;

    const struct linkedit_data_command *ldc = (const struct linkedit_data_command *)fixlc;
    const uint8_t *fbase = base + ldc->dataoff;
    const struct rek_fixups_header *fh = (const struct rek_fixups_header *)fbase;
    if (fh->imports_format != 1 && fh->imports_format != 2 && fh->imports_format != 3) return 0;

    const struct rek_starts_in_image *si =
        (const struct rek_starts_in_image *)(fbase + fh->starts_offset);
    const char *symbolPool = (const char *)(fbase + fh->symbols_offset);

    int found = 0;
    for (uint32_t seg = 0; seg < si->seg_count; seg++) {
        uint32_t off = si->seg_info_offset[seg];
        if (off == 0) continue;
        const struct rek_starts_in_segment *ss =
            (const struct rek_starts_in_segment *)((const uint8_t *)si + off);
        if (ss->page_count == 0) continue;
        int stride = (ss->pointer_format == REK_FMT_ARM64E ||
                      ss->pointer_format == REK_FMT_ARM64E_USERLAND ||
                      ss->pointer_format == REK_FMT_ARM64E_USERLAND24) ? 8 : 4;
        for (uint16_t pg = 0; pg < ss->page_count; pg++) {
            uint16_t start = ss->page_start[pg];
            if (start == 0xFFFF || start == 0x8000) continue;
            uint8_t *cursor = (uint8_t *)(base + slide) + ss->segment_offset +
                              (uint64_t)pg * ss->page_size + start;
            for (int guard = 0; guard < 100000; guard++) {
                uint64_t raw = *(volatile uint64_t *)cursor;
                uint64_t next = 0;
                uint32_t ordinal = 0;
                int isBind = 0;
                if (stride == 8) {
                    struct rek_ptrarm64e_bind b;
                    memcpy(&b, &raw, 8);
                    isBind = (int)b.bind;
                    ordinal = b.ordinal;
                    next = b.next;
                } else {
                    struct rek_ptr64_bind b;
                    memcpy(&b, &raw, 8);
                    isBind = (int)b.bind;
                    ordinal = b.ordinal;
                    next = b.next;
                }
                if (isBind && ordinal < fh->imports_count) {
                    const uint8_t *imp = fbase + fh->imports_offset +
                                         (size_t)ordinal * (fh->imports_format == 3 ? 8 : 4);
                    uint64_t val = 0;
                    memcpy(&val, imp, fh->imports_format == 3 ? 8 : 4);
                    uint32_t nameOff = fh->imports_format == 3
                        ? (uint32_t)((val >> 32) & 0xFFFFFFFF)
                        : (uint32_t)(val >> 9);
                    const char *name = symbolPool + nameOff;
                    for (size_t i = 0; i < n; i++) {
                        if (!rek_name_matches(name, rebs[i].name)) continue;
                        if (rebs[i].replaced && *rebs[i].replaced == NULL) {
                            *rebs[i].replaced = (void *)(uintptr_t)raw;
                        }
                        if (rek_page_write(cursor, 8)) {
                            uint64_t plain = (uint64_t)(uintptr_t)rebs[i].replacement;
                            plain |= (next << 51); // keep "next" stride bits, clear bind
                            *(volatile uint64_t *)cursor = plain;
                            found++;
                            g_rebound++;
                        }
                        break;
                    }
                }
                if (next == 0) break;
                cursor += next * stride;
            }
        }
    }
    (void)symlc;
    return found;
}

/// Classic __la_symbol_ptr / __nl_symbol_ptr / __got rebinding.
static int rek_walk_classic(const struct mach_header_64 *h, intptr_t slide,
                            REKRebinding *rebs, size_t n) {
    const struct symtab_command *symtab = NULL;
    const struct dysymtab_command *dysym = NULL;
    const uint8_t *p = (const uint8_t *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < 8) break;
        if (lc->cmd == LC_SYMTAB) symtab = (const struct symtab_command *)lc;
        if (lc->cmd == LC_DYSYMTAB) dysym = (const struct dysymtab_command *)lc;
        p += lc->cmdsize;
    }
    if (!symtab || !dysym) return 0;

    const struct nlist_64 *syms = (const struct nlist_64 *)((const uint8_t *)h + symtab->symoff);
    const char *strs = (const char *)h + symtab->stroff;
    const uint32_t *indirect = (const uint32_t *)((const uint8_t *)h + dysym->indirectsymoff);

    int found = 0;
    const uint8_t *lcptr = (const uint8_t *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)lcptr;
        if (lc->cmd != LC_SEGMENT_64) { lcptr += lc->cmdsize; continue; }
        const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
        const struct section_64 *sect = (const struct section_64 *)(seg + 1);
        for (uint32_t s = 0; s < seg->nsects; s++) {
            uint32_t type = sect[s].flags & SECTION_TYPE;
            if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS &&
                type != S_THREAD_LOCAL_VARIABLE_POINTERS) continue;
            uint32_t count = (uint32_t)(sect[s].size / 8);
            uint8_t *base = (uint8_t *)(h + slide) + sect[s].offset;
            for (uint32_t k = 0; k < count; k++) {
                uint32_t symIdx = indirect[sect[s].reserved1 + k];
                if (symIdx == INDIRECT_SYMBOL_ABS || symIdx == INDIRECT_SYMBOL_LOCAL) continue;
                const char *name = strs + syms[symIdx].n_un.n_strx;
                for (size_t r = 0; r < n; r++) {
                    if (!rek_name_matches(name, rebs[r].name)) continue;
                    void **slot = (void **)(base + k * 8);
                    if (rebs[r].replaced && *rebs[r].replaced == NULL) *rebs[r].replaced = *slot;
                    if (rek_page_write(slot, 8)) {
                        *slot = rebs[r].replacement;
                        found++;
                        g_rebound++;
                    }
                    break;
                }
            }
        }
        lcptr += lc->cmdsize;
    }
    return found;
}

int rek_rebind_symbols(REKRebinding rebindings[], size_t count) {
    if (!rebindings || count == 0) return 0;
    g_rebound = 0;
    g_images = 0;
    g_skipped = 0;
    g_chained_images = 0;
    uint32_t total = _dyld_image_count();
    for (uint32_t i = 0; i < total; i++) {
        const struct mach_header_64 *h = rek_hdr(i);
        if (!h) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        g_images++;
        int r = rek_walk_chained(h, slide, rebindings, count);
        if (r < 0) {
            r = rek_walk_classic(h, slide, rebindings, count);
            if (r == 0) g_skipped++;
        } else {
            g_chained_images++;
        }
    }
    return g_rebound;
}

uint32_t REKClassMethodCount(Class cls) {
    if (!cls) return 0;
    uint32_t n = 0;
    Method *list = class_copyMethodList(cls, &n);
    if (list) free(list);
    return n;
}

uint32_t REKClassIvarCount(Class cls) {
    if (!cls) return 0;
    uint32_t n = 0;
    Ivar *list = class_copyIvarList(cls, &n);
    if (list) free(list);
    return n;
}

uint32_t REKClassProtocolCount(Class cls) {
    if (!cls) return 0;
    uint32_t n = 0;
    Protocol *__unsafe_unretained *list = class_copyProtocolList(cls, &n);
    if (list) free(list);
    return n;
}
