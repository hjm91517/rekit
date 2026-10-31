#ifndef REK_INTERPOSE_H
#define REK_INTERPOSE_H

#include <stddef.h>
#include <stdint.h>

/// One symbol interposition request.
typedef struct {
    const char *name;   ///< imported symbol name, e.g. "ptrace"
    void *replacement;  ///< function pointer that should win
    void **replaced;    ///< out: original implementation (may be NULL to ignore)
} REKRebinding;

/// Rewrites imported-symbol pointers in every loaded image.
/// Handles classic __la_symbol_ptr/__got sections and LC_DYLD_CHAINED_FIXUPS images.
/// Returns number of pointers rewritten. Thread-unsafe, call once at startup.
int rek_rebind_symbols(REKRebinding rebindings[], size_t count);

/// Number of load images that carry chained fixups (informational, for UI status).
int rek_chained_fixup_image_count(void);

/// Number of images visited by the last rek_rebind_symbols call.
int rek_last_image_count(void);

/// Number of images skipped by the last call (no usable bind info).
int rek_last_skipped_count(void);

/// 1 when the main executable is built with chained fixups.
int rek_main_has_chained_fixups(void);

#endif
