#ifndef MCPMAC_MIL_INSPECTOR_H
#define MCPMAC_MIL_INSPECTOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Inspect a sequence of MIL op names and map them to OpFamily.
// Invokes hook for each mapped OpFamily.
// Returns 0 on success, or non-zero if hook denies an op.
typedef int (*mil_admit_hook_t)(int op_family, void *context);

int mil_inspect_operations(const char *const *op_names, size_t count,
                           mil_admit_hook_t hook, void *context);

#ifdef __cplusplus
}
#endif

#endif // MCPMAC_MIL_INSPECTOR_H
