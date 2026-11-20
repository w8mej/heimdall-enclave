#include "mil_inspector.h"
#include <string.h>

// Explicit reference fixture vocabulary, not a classifier for real MIL
// programs.
static int map_mil_op_to_family(const char *name) {
  if (!name)
    return -1;
  const char *families[] = {"causal_decode",
                            "classifier_head",
                            "bidirectional_mask",
                            "denoise_step",
                            "persistent_state_scan",
                            "byte_decode",
                            "concept_diffusion",
                            "recurrent_depth_loop",
                            "draft_tree",
                            "jepa_predict",
                            "mpc_rollout"};
  for (int i = 0; i < 11; ++i)
    if (strcmp(name, families[i]) == 0)
      return i;
  return -1;
}
int mil_inspect_operations(const char *const *names, size_t count,
                           mil_admit_hook_t hook, void *context) {
  if (!names || count == 0 || !hook || !context)
    return -1;
  for (size_t i = 0; i < count; i++) {
    int family = map_mil_op_to_family(names[i]);
    if (family < 0)
      return -1;
    int rc = hook(family, context);
    if (rc != 0)
      return rc;
  }
  return 0;
}
