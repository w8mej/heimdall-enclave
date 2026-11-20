#include "holder_policy.h"
#include <stddef.h>
#include <string.h>
_Static_assert(sizeof(struct mcpmac_mapping_evidence) == 128,
               "mapping evidence ABI");

/* SDK-independent values from mach/vm_region.h and sys/proc_info.h, checked
 * against the native SDK by holder_maps.c. */
#define REGION_SUBMAP 1u
#define SHARE_COW 1u
#define SHARE_PRIVATE 2u
#define SHARE_EMPTY 3u
#define SHARE_SHARED 4u
#define SHARE_TRUE 5u
#define SHARE_PRIVATE_ALIAS 6u
#define SHARE_SHARED_ALIAS 7u

static int range(uint64_t address, uint64_t size) {
  return size != 0 && address <= UINT64_MAX - size;
}
static int contains(uint64_t outer, uint64_t outer_size, uint64_t inner,
                    uint64_t inner_size) {
  return range(outer, outer_size) && range(inner, inner_size) &&
         outer <= inner && inner + inner_size <= outer + outer_size;
}
int mcpmac_holder_mapping_verdict(const struct mcpmac_mapping_evidence *e,
                                  uint64_t dev, uint64_t ino) {
  if (!e || !dev || !ino || e->source_valid != 1 || e->source_submap != 0 ||
      e->source_external > 1 || e->address < e->cursor ||
      !range(e->address, e->size))
    return -1;
  if (!e->source_external) {
    /* SHORT_INFO walks the complete shadow chain without resident-page
     * filtering. EMPTY additionally needs TOP_INFO's null-object result:
     * SHORT_INFO also reports EMPTY for non-null physical objects. */
    switch (e->source_share) {
    case SHARE_COW:
    case SHARE_PRIVATE:
    case SHARE_SHARED:
    case SHARE_TRUE:
    case SHARE_PRIVATE_ALIAS:
    case SHARE_SHARED_ALIAS:
      return 0;
    case SHARE_EMPTY:
      return e->source_top_valid == 1 && e->source_top_share == SHARE_EMPTY
                 ? 0
                 : -1;
    default:
      return -1;
    }
  }
  if (e->metadata_valid != 1 || !e->device || !e->inode ||
      (e->metadata_flags & REGION_SUBMAP) || e->metadata_from_mirror > 1)
    return -1;
  if (e->metadata_from_mirror) {
    /* A remap that copied away the vnode produces an internal object. It
     * cannot authorize absence for the original external mapping. */
    if (e->mirror_valid != 1 || e->mirror_external != 1 ||
        e->mirror_submap != 0 || e->mirror_current != 0 ||
        e->mirror_maximum != 0 || e->mirror_size > e->size ||
        !contains(e->metadata_address, e->metadata_size, e->mirror_address,
                  e->mirror_size))
      return -1;
  } else if (!contains(e->metadata_address, e->metadata_size, e->address,
                       e->size))
    return -1;
  return e->device == dev && e->inode == ino ? 1 : 0;
}
int mcpmac_holder_donation_verdict(const uint32_t sender[8],
                                   const uint32_t task[8], int task_pid,
                                   int captured_pid, uint32_t captured_uid,
                                   uint64_t captured_birth,
                                   uint32_t captured_version) {
  return sender && task && captured_pid > 1 && captured_birth != 0 &&
         task_pid == captured_pid && sender[5] == (uint32_t)captured_pid &&
         sender[1] == captured_uid && sender[3] == captured_uid &&
         sender[7] == captured_version &&
         memcmp(sender, task, 8 * sizeof(uint32_t)) == 0;
}
