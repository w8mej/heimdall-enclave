/* SDK-sized mapped-vnode observation; private identity operations are isolated
 * here and dynamically resolved. No bare-PID signal fallback is permitted.
 * SPI source/availability evidence:
 * docs/remediation/phase1-20261113/evidence/reviews.
 */
#include <dlfcn.h>
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/types.h>
#include <time.h>

extern int depot_holder_maps_observe(int, uint32_t, uint64_t, uint32_t,
                                      mach_port_t, uint64_t, uint64_t, double);

struct unique_info {
  uint8_t uuid[16];
  uint64_t unique, parent_unique;
  int32_t version, parent_version;
  uint64_t reserved2, reserved3;
};
_Static_assert(sizeof(struct unique_info) == 56, "unique-info API size");
static int identity(int pid, struct unique_info *u, struct proc_bsdinfo *b) {
  struct unique_info after;
  if (proc_pidinfo(pid, 17, 0, u, sizeof(*u)) != sizeof(*u) ||
      proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, b, sizeof(*b)) != sizeof(*b) ||
      proc_pidinfo(pid, 17, 0, &after, sizeof(after)) != sizeof(after) ||
      u->unique != after.unique || u->version != after.version ||
      b->pbi_uid != b->pbi_ruid)
    return -1;
  return 0;
}
int depot_holder_capture(int pid, uint32_t *uid, uint64_t *birth,
                          uint32_t *version) {
  struct unique_info u;
  struct proc_bsdinfo b;
  if (identity(pid, &u, &b))
    return -1;
  *uid = b.pbi_uid;
  *birth = u.unique;
  *version = (uint32_t)u.version;
  return 0;
}
static int same(int pid, uint32_t uid, uint64_t birth, uint32_t version) {
  struct unique_info u;
  struct proc_bsdinfo b;
  return identity(pid, &u, &b) == 0 && u.unique == birth &&
         (uint32_t)u.version == version && b.pbi_uid == uid;
}
static double monotonic_seconds(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    return -1;
  return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}
int depot_holder_signal(int pid, uint32_t uid, uint64_t birth,
                         uint32_t version, int sig) {
  typedef int (*signal_fn)(audit_token_t *, int);
  signal_fn send =
      (signal_fn)dlsym(RTLD_DEFAULT, "proc_signal_with_audittoken");
  if (!send)
    return ENOSYS;
  if (!same(pid, uid, birth, version))
    return ESRCH;
  audit_token_t token;
  memset(&token, 0, sizeof(token));
  /* Kernel signal SPI compares PID and pidversion. This identity selector is
   * built from kernel queries; it is NOT an IPC authentication credential. */
  token.val[5] = (uint32_t)pid;
  token.val[7] = version;
  return send(&token, sig);
}
/* A vnode fileport retains its fileglob after the last numeric FD closes and
 * can later recreate an FD. Its name belongs to the observed task's namespace:
 * this observer only queries it, never adopts/deallocates or dereferences it.
 * Zero list bytes are usable only with a successful errno-cleared query.
 * This additional dimension does not resolve opaque external-pager mappings
 * or make the separate FD/map/fileport samples an atomic lifetime census. */
static int fileports_observe(int pid, uint32_t uid, uint64_t birth,
                             uint32_t version, uint64_t dev, uint64_t ino,
                             double deadline) {
  const size_t limit = 65536;
  double now = monotonic_seconds();
  if (!dev || !ino || !(now >= 0 && now < deadline) ||
      !same(pid, uid, birth, version))
    return -1;
  now = monotonic_seconds();
  if (!(now >= 0 && now < deadline))
    return -1;
  errno = 0;
  int need = proc_pidinfo(pid, PROC_PIDLISTFILEPORTS, 0, NULL, 0);
  if (need < 0 || errno || need % (int)sizeof(struct proc_fileportinfo) != 0 ||
      (size_t)need > limit * sizeof(struct proc_fileportinfo))
    return -1;
  now = monotonic_seconds();
  if (!(now >= 0 && now < deadline))
    return -1;
  size_t capacity = (size_t)need / sizeof(struct proc_fileportinfo);
  capacity = capacity > limit - 64 ? limit : capacity + 64;
  struct proc_fileportinfo *ports = calloc(capacity, sizeof(*ports));
  if (!ports)
    return -1;
  now = monotonic_seconds();
  if (!(now >= 0 && now < deadline)) {
    free(ports);
    return -1;
  }
  errno = 0;
  int got = proc_pidinfo(pid, PROC_PIDLISTFILEPORTS, 0, ports,
                         (int)(capacity * sizeof(*ports)));
  if (got < 0 || errno || (size_t)got > capacity * sizeof(*ports) ||
      got % (int)sizeof(*ports) != 0) {
    free(ports);
    return -1;
  }
  now = monotonic_seconds();
  if (!(now >= 0 && now < deadline)) {
    free(ports);
    return -1;
  }
  int complete = (size_t)got < capacity * sizeof(*ports), held = 0;
  for (size_t i = 0; i < (size_t)got / sizeof(*ports); i++) {
    now = monotonic_seconds();
    if (!(now >= 0 && now < deadline)) {
      complete = 0;
      break;
    }
    if (ports[i].proc_fdtype != PROX_FDTYPE_VNODE)
      continue;
    if (!MACH_PORT_VALID(ports[i].proc_fileport)) {
      complete = 0;
      continue;
    }
    struct vnode_fdinfowithpath vnode;
    memset(&vnode, 0, sizeof(vnode));
    errno = 0;
    int count = proc_pidfileportinfo(pid, ports[i].proc_fileport,
                                     PROC_PIDFILEPORTVNODEPATHINFO, &vnode,
                                     sizeof(vnode));
    if (count != (int)sizeof(vnode) || errno ||
        !vnode.pvip.vip_vi.vi_stat.vst_dev ||
        !vnode.pvip.vip_vi.vi_stat.vst_ino) {
      complete = 0;
      continue;
    }
    if ((uint64_t)vnode.pvip.vip_vi.vi_stat.vst_dev == dev &&
        vnode.pvip.vip_vi.vi_stat.vst_ino == ino) {
      held = 1;
      break;
    }
  }
  free(ports);
  if (!same(pid, uid, birth, version))
    return -1;
  now = monotonic_seconds();
  if (!(now >= 0 && now < deadline))
    return -1;
  return held ? 1 : (complete ? 0 : -1);
}
#ifdef depot_HOLDER_FILEPORT_PROBE
/* Exact production helper exposed only in the separately compiled owned probe.
 */
int depot_holder_fileports_probe(int pid, uint32_t uid, uint64_t birth,
                                  uint32_t version, uint64_t dev, uint64_t ino,
                                  double deadline) {
  return fileports_observe(pid, uid, birth, version, dev, ino, deadline);
}
#endif
int depot_holder_observe(int pid, uint32_t uid, uint64_t birth,
                          uint32_t version, uint64_t dev, uint64_t ino) {
  if (!same(pid, uid, birth, version))
    return -1;
  const double started = monotonic_seconds();
  if (started < 0)
    return -1;
  const double deadline = started + 1.0;
  int complete = 1, held = 0;
  int need = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
  if (need < 0 || need > (int)(65536 * sizeof(struct proc_fdinfo)))
    return -1;
  size_t capacity = (size_t)need / sizeof(struct proc_fdinfo) + 64;
  struct proc_fdinfo *fds = calloc(capacity, sizeof(*fds));
  if (!fds)
    return -1;
  int got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds,
                         (int)(capacity * sizeof(*fds)));
  if (got < 0 || got >= (int)(capacity * sizeof(*fds)) ||
      got % (int)sizeof(*fds) != 0) {
    free(fds);
    return -1;
  }
  if (got == 0)
    complete = 0; /* cannot distinguish a denied query from no FDs */
  for (size_t i = 0; i < (size_t)got / sizeof(*fds); i++) {
    if (monotonic_seconds() > deadline) {
      complete = 0;
      break;
    }
    if (fds[i].proc_fdtype != PROX_FDTYPE_VNODE)
      continue;
    struct vnode_fdinfo v;
    if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDVNODEINFO, &v,
                       sizeof(v)) != sizeof(v)) {
      complete = 0;
      continue;
    }
    if ((uint64_t)v.pvi.vi_stat.vst_dev == dev &&
        v.pvi.vi_stat.vst_ino == ino) {
      held = 1;
      break;
    }
  }
  free(fds);
  if (!held) {
    int fileports =
        fileports_observe(pid, uid, birth, version, dev, ino, deadline);
    if (fileports == 1)
      held = 1;
    else if (fileports != 0)
      complete = 0;
  }
  if (!held) {
    /* A production supervisor may obtain a read-capable right through the
     * supported kernel policy. Denial is not absence and does not relax
     * signing/entitlements. The original conservative path remains usable
     * for positive holder discovery when this capability is unavailable. */
    typedef int (*read_fn)(mach_port_t, int, mach_port_t *);
    read_fn request = (read_fn)dlsym(RTLD_DEFAULT, "task_read_for_pid");
    mach_port_t read_port = MACH_PORT_NULL;
    int acquired = request ? request(mach_task_self(), pid, &read_port) : -1;
    if (acquired == 0 && MACH_PORT_VALID(read_port)) {
      int mappings = depot_holder_maps_observe(pid, uid, birth, version,
                                                read_port, dev, ino, deadline);
      mach_port_deallocate(mach_task_self(), read_port);
      if (!same(pid, uid, birth, version))
        return -1;
      return mappings == 1 ? 1 : (mappings == 0 && complete ? 0 : -1);
    }
    if (MACH_PORT_VALID(read_port))
      mach_port_deallocate(mach_task_self(), read_port);
    uint64_t address = 0;
    int ended = 0;
    for (size_t count = 0; count < 65536; count++) {
      if (monotonic_seconds() > deadline) {
        complete = 0;
        break;
      }
      struct proc_regionwithpathinfo region;
      memset(&region, 0, sizeof(region));
      errno = 0;
      int n = proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, address, &region,
                           sizeof(region));
      if (n == 0 && errno == EINVAL) {
        ended = 1;
        break;
      }
      if (n != sizeof(region)) {
        complete = 0;
        break;
      }
      /* INFO1 reports zero vnode fields both for anonymous mappings and
       * failed vnode/pager queries. It cannot prove absence in that
       * case. Retain uncertainty; never clear a publication on it. */
      if ((region.prp_prinfo.pri_flags & PROC_REGION_SUBMAP) ||
          region.prp_vip.vip_vi.vi_stat.vst_ino == 0 ||
          region.prp_vip.vip_vi.vi_stat.vst_dev == 0)
        complete = 0;
      if ((uint64_t)region.prp_vip.vip_vi.vi_stat.vst_dev == dev &&
          region.prp_vip.vip_vi.vi_stat.vst_ino == ino) {
        held = 1;
        break;
      }
      uint64_t start = region.prp_prinfo.pri_address,
               size = region.prp_prinfo.pri_size;
      if (size == 0 || start > UINT64_MAX - size || start + size <= address) {
        complete = 0;
        break;
      }
      address = start + size;
    }
    if (!ended && !held)
      complete = 0;
  }
  if (!same(pid, uid, birth, version))
    return -1;
  return held ? 1 : (complete ? 0 : -1);
}
