#include "mlx_shim.h"

// Reference callback fixture only: MLX is not linked. Context belongs to this
// synchronous invocation; there is no global registration window or default
// allow.
int mlx_construct_operator(int op_family, mlx_operator_hook_t hook,
                           void *context) {
  if (!hook || !context)
    return -1;
  return hook(op_family, context);
}

int mlx_construct_graph(const int *ops, size_t count, mlx_operator_hook_t hook,
                        void *context) {
  if (!ops || count == 0 || !hook || !context)
    return -1;
  for (size_t i = 0; i < count; i++) {
    int rc = mlx_construct_operator(ops[i], hook, context);
    if (rc != 0)
      return rc;
  }
  return 0;
}
