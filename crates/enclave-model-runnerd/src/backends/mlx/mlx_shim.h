#ifndef depot_MLX_SHIM_H
#define depot_MLX_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum MlxOpFamily {
  MLX_OP_CAUSAL_DECODE = 0,
  MLX_OP_CLASSIFIER_HEAD = 1,
  MLX_OP_BIDIRECTIONAL_MASK = 2,
  MLX_OP_DENOISE_STEP = 3,
  MLX_OP_PERSISTENT_STATE_SCAN = 4,
  MLX_OP_BYTE_DECODE = 5,
  MLX_OP_CONCEPT_DIFFUSION = 6,
  MLX_OP_RECURRENT_DEPTH_LOOP = 7,
  MLX_OP_DRAFT_TREE = 8,
  MLX_OP_JEPA_PREDICT = 9,
  MLX_OP_MPC_ROLLOUT = 10,
};

typedef int (*mlx_operator_hook_t)(int op_family, void *context);

int mlx_construct_operator(int op_family, mlx_operator_hook_t hook,
                           void *context);
int mlx_construct_graph(const int *op_families, size_t count,
                        mlx_operator_hook_t hook, void *context);

#ifdef __cplusplus
}
#endif

#endif // depot_MLX_SHIM_H
