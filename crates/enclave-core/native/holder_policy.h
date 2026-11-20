#ifndef depot_HOLDER_POLICY_H
#define depot_HOLDER_POLICY_H
#include <stdint.h>
/* Fixed-width evidence only. Native SDK queries supply these fields; the
 * decision engine is also compiled/tested on other supported build hosts. */
struct depot_mapping_evidence {
  uint64_t cursor, address, size;
  uint64_t mirror_address, mirror_size;
  uint64_t metadata_address, metadata_size, device, inode;
  uint32_t source_valid, source_external, source_submap, source_share;
  uint32_t source_top_valid, source_top_share, metadata_from_mirror;
  uint32_t mirror_valid, mirror_external, mirror_submap;
  uint32_t mirror_current, mirror_maximum, metadata_valid, metadata_flags;
};
/* 1 held, 0 complete nonmatch, -1 unknown. Zero-vnode, failed/short queries,
 * unsupported pagers and an external-to-internal copy never prove absence. */
int depot_holder_mapping_verdict(const struct depot_mapping_evidence *,
                                  uint64_t, uint64_t);
/* A delegated task must be the authenticated sender's current process image,
 * independently captured through the kernel. No declared PID is accepted. */
int depot_holder_donation_verdict(const uint32_t sender[8],
                                   const uint32_t task[8], int task_pid,
                                   int captured_pid, uint32_t captured_uid,
                                   uint64_t captured_birth,
                                   uint32_t captured_version);
#endif
