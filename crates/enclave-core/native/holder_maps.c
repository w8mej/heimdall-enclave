/* Read-capable task-map observation. The observer does not dereference
 * mirrors or call memory-read APIs. External leaves nested in submaps can be
 * mirrored for one page with both protections permanently NONE, then queried
 * for numeric vnode metadata. The kernel may internally copy that page for
 * some COW modes; a mirror that loses external backing proves nothing.
 * Every unavailable/unsupported/changed observation remains incomplete. */
#include "holder_policy.h"
#include <dlfcn.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task_info.h>
#include <mach/vm_region.h>
#include <stdint.h>
#include <string.h>
#include <sys/proc_info.h>
#include <time.h>
#include <unistd.h>
#ifdef depot_HOLDER_TRACE
#include <stdio.h>
#define TRACE(...) fprintf(stderr, __VA_ARGS__)
#else
#define TRACE(...) ((void)0)
#endif

_Static_assert(SM_COW == 1 && SM_PRIVATE == 2 && SM_EMPTY == 3 &&
                   SM_SHARED == 4 && SM_TRUESHARED == 5 &&
                   SM_PRIVATE_ALIASED == 6 && SM_SHARED_ALIASED == 7,
               "share-mode SDK values");
_Static_assert(PROC_REGION_SUBMAP == 1, "region submap SDK value");
_Static_assert(sizeof(audit_token_t) ==
                   TASK_AUDIT_TOKEN_COUNT * sizeof(natural_t),
               "audit-token SDK size");
extern int depot_holder_capture(int, uint32_t *, uint64_t *, uint32_t *);
typedef kern_return_t (*remap_fn)(mach_port_t, mach_vm_address_t *,
                                  mach_vm_size_t, mach_vm_offset_t, int,
                                  mach_port_t, mach_vm_address_t, boolean_t,
                                  vm_prot_t *, vm_prot_t *, vm_inherit_t);
static int within(double deadline) {
  struct timespec now;
  return clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
         (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0 < deadline;
}
static int same(int pid, uint32_t uid, uint64_t birth, uint32_t version,
                mach_port_t port) {
  uint32_t observed_uid = 0, observed_version = 0;
  uint64_t observed_birth = 0;
  audit_token_t token;
  memset(&token, 0, sizeof(token));
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  pid_t task_pid = 0;
  return pid_for_task(port, &task_pid) == KERN_SUCCESS && task_pid == pid &&
         task_info(port, TASK_AUDIT_TOKEN, (task_info_t)&token, &count) ==
             KERN_SUCCESS &&
         count == TASK_AUDIT_TOKEN_COUNT && token.val[5] == (uint32_t)pid &&
         token.val[1] == uid && token.val[3] == uid &&
         token.val[7] == version &&
         depot_holder_capture(pid, &observed_uid, &observed_birth,
                               &observed_version) == 0 &&
         observed_uid == uid && observed_birth == birth &&
         observed_version == version;
}
static kern_return_t leaf(mach_port_t port, mach_vm_address_t *address,
                          mach_vm_size_t *size,
                          vm_region_submap_short_info_data_64_t *info) {
  natural_t depth = 16;
  mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
  memset(info, 0, sizeof(*info));
  *size = 0;
  kern_return_t kr = mach_vm_region_recurse(
      port, address, size, &depth, (vm_region_recurse_info_t)info, &count);
  if (kr == KERN_SUCCESS && (count != VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 ||
                             depth > 16 || info->is_submap))
    return KERN_INVALID_ARGUMENT;
  return kr;
}
static int covers(uint64_t address, uint64_t size, uint64_t inner,
                  uint64_t length) {
  return size && length && address <= UINT64_MAX - size &&
         inner <= UINT64_MAX - length && address <= inner &&
         inner + length <= address + size;
}
static void vnode(int pid, uint64_t address,
                  struct depot_mapping_evidence *e) {
  struct proc_regionwithpathinfo region;
  memset(&region, 0, sizeof(region));
  if (proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, address, &region,
                   sizeof(region)) != sizeof(region))
    return;
  e->metadata_valid = 1;
  e->metadata_address = region.prp_prinfo.pri_address;
  e->metadata_size = region.prp_prinfo.pri_size;
  e->metadata_flags = region.prp_prinfo.pri_flags;
  e->device = region.prp_vip.vip_vi.vi_stat.vst_dev;
  e->inode = region.prp_vip.vip_vi.vi_stat.vst_ino;
}
static int mirrored(mach_port_t port, struct depot_mapping_evidence *e,
                    remap_fn remap) {
  const uint64_t page = (uint64_t)getpagesize();
  if (!remap || !page || e->size < page || e->address % page)
    return -1;
  mach_vm_address_t local = 0;
  vm_prot_t current = VM_PROT_NONE, maximum = VM_PROT_NONE;
  if (remap(mach_task_self(), &local, page, 0, VM_FLAGS_ANYWHERE, port,
            e->address, FALSE, &current, &maximum,
            VM_INHERIT_NONE) != KERN_SUCCESS)
    return -1;
  e->mirror_address = local;
  e->mirror_size = page;
  e->mirror_current = current;
  e->mirror_maximum = maximum;
  vm_region_submap_short_info_data_64_t info;
  mach_vm_address_t actual = local;
  mach_vm_size_t size = 0;
  if (leaf(mach_task_self(), &actual, &size, &info) == KERN_SUCCESS &&
      covers(actual, size, local, page)) {
    e->mirror_valid = 1;
    e->mirror_external = info.external_pager;
    e->mirror_submap = info.is_submap;
    if (e->source_external) {
      /* A copy that lost external backing cannot prove anything about
       * the original vnode, including absence. The policy enforces it. */
      e->metadata_valid = 0;
      e->device = 0;
      e->inode = 0;
      e->metadata_from_mirror = 1;
      vnode(getpid(), local, e);
    }
  }
  return mach_vm_deallocate(mach_task_self(), local, page) == KERN_SUCCESS ? 0
                                                                           : -1;
}
/* A remap of a null reservation can materialize an anonymous object.
 * Therefore query TOP_INFO on the original flat entry instead. INFO1 proves
 * this address is not a top-level submap wrapper; it is not used as vnode
 * absence evidence. Nested or mismatched ranges remain unsupported. */
static void original_top(mach_port_t port, int pid,
                         struct depot_mapping_evidence *e) {
  vnode(pid, e->address, e);
  if (!e->metadata_valid || (e->metadata_flags & PROC_REGION_SUBMAP) ||
      !covers(e->metadata_address, e->metadata_size, e->address, e->size))
    return;
  vm_region_top_info_data_t top;
  memset(&top, 0, sizeof(top));
  mach_msg_type_number_t count = VM_REGION_TOP_INFO_COUNT;
  mach_port_t object = MACH_PORT_NULL;
  mach_vm_address_t actual = e->address;
  mach_vm_size_t size = 0;
  int kr = mach_vm_region(port, &actual, &size, VM_REGION_TOP_INFO,
                          (vm_region_info_t)&top, &count, &object);
  if (object)
    mach_port_deallocate(mach_task_self(), object);
  if (kr == KERN_SUCCESS && count == VM_REGION_TOP_INFO_COUNT &&
      covers(actual, size, e->address, e->size)) {
    e->source_top_valid = 1;
    e->source_top_share = top.share_mode;
  }
}
int depot_holder_maps_observe(int pid, uint32_t uid, uint64_t birth,
                               uint32_t version, mach_port_t port, uint64_t dev,
                               uint64_t ino, double deadline) {
  if (!within(deadline) || !same(pid, uid, birth, version, port)) {
    TRACE("holder_maps begin deadline_or_identity_failed\n");
    return -1;
  }
  remap_fn remap = (remap_fn)dlsym(RTLD_DEFAULT, "mach_vm_remap_new");
  int complete = 1, held = 0, ended = 0;
  uint64_t cursor = 0;
  for (unsigned count = 0; count < 65536; count++) {
    if (!within(deadline)) {
      TRACE("holder_maps deadline cursor=%llu count=%u\n",
            (unsigned long long)cursor, count);
      complete = 0;
      break;
    }
    vm_region_submap_short_info_data_64_t info;
    mach_vm_address_t address = cursor;
    mach_vm_size_t size = 0;
    int kr = leaf(port, &address, &size, &info);
    if (kr == KERN_INVALID_ADDRESS) {
      ended = 1;
      break;
    }
    if (kr != KERN_SUCCESS || !size || address < cursor ||
        address > UINT64_MAX - size) {
      TRACE(
          "holder_maps leaf_failed kr=%d cursor=%llu address=%llu size=%llu\n",
          kr, (unsigned long long)cursor, (unsigned long long)address,
          (unsigned long long)size);
      complete = 0;
      break;
    }
    struct depot_mapping_evidence e;
    memset(&e, 0, sizeof(e));
    e.cursor = cursor;
    e.address = address;
    e.size = size;
    e.source_valid = 1;
    e.source_external = info.external_pager;
    e.source_submap = info.is_submap;
    e.source_share = info.share_mode;
    if (info.external_pager) {
      vnode(pid, address, &e);
      if (!e.metadata_valid || !e.device || !e.inode ||
          (e.metadata_flags & PROC_REGION_SUBMAP) ||
          !covers(e.metadata_address, e.metadata_size, address, size)) {
        if (!within(deadline) || mirrored(port, &e, remap) != 0) {
          TRACE("holder_maps mirror_failed address=%llu size=%llu external=%u "
                "share=%u object=%u flags=%u\n",
                (unsigned long long)address, (unsigned long long)size,
                info.external_pager, info.share_mode, info.object_id,
                info.flags);
          complete = 0;
          cursor = address + size;
          continue;
        }
      }
    } else if (info.share_mode == SM_EMPTY) {
      if (!within(deadline)) {
        complete = 0;
        break;
      }
      original_top(port, pid, &e);
    }
    int verdict = depot_holder_mapping_verdict(&e, dev, ino);
    if (verdict == 1) {
      held = 1;
      break;
    }
    if (verdict != 0) {
      TRACE("holder_maps unknown address=%llu size=%llu source_external=%u "
            "source_share=%u object=%u flags=%u source_top_valid=%u "
            "source_top_share=%u mirror_valid=%u mirror_external=%u "
            "mirror_current=%u mirror_max=%u metadata_valid=%u "
            "metadata_flags=%u dev=%llu ino=%llu\n",
            (unsigned long long)address, (unsigned long long)size,
            e.source_external, e.source_share, info.object_id, info.flags,
            e.source_top_valid, e.source_top_share, e.mirror_valid,
            e.mirror_external, e.mirror_current, e.mirror_maximum,
            e.metadata_valid, e.metadata_flags, (unsigned long long)e.device,
            (unsigned long long)e.inode);
      complete = 0;
    }
    cursor = address + size;
  }
  if (!same(pid, uid, birth, version, port))
    return -1;
  return held ? 1 : (ended && complete ? 0 : -1);
}
