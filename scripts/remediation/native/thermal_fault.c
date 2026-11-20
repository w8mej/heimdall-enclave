/* Disposable DYLD probe only; no production daemon or OS settings are changed.
 */
#include <errno.h>
#include <notify.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#ifndef depot_FAULT_KIND
#error depot_FAULT_KIND required
#endif
static _Atomic uint64_t paths = 0;
static _Atomic int thermal_token = -1;
static _Atomic int thermal_fd = -1;
#define FIXTURE_TOKEN 0x4d4350
uint64_t depot_thermal_fault_snapshot(void) {
  return depot_FAULT_KIND | (atomic_load(&paths) << 8);
}
static uint32_t probe_register(const char *name, int *fd, int flags,
                               int *token) {
  if (!name || strcmp(name, "com.apple.system.thermalpressurelevel") != 0)
    return notify_register_file_descriptor(name, fd, flags, token);
  atomic_fetch_or(&paths, 1);
#if depot_FAULT_KIND == 1
  return NOTIFY_STATUS_FAILED;
#elif depot_FAULT_KIND == 2
  uint32_t rc = notify_register_file_descriptor(name, fd, flags, token);
  if (rc == NOTIFY_STATUS_OK) {
    atomic_store(&thermal_token, *token);
    atomic_store(&thermal_fd, *fd);
  }
  return rc;
#else
  /* Native read EOF/error exercise: construct a descriptor only this probe
     owns, report nominal initially, then let production Rust fail its read. */
  (void)flags;
  int ends[2];
  if (pipe(ends) != 0)
    return NOTIFY_STATUS_FAILED;
  close(ends[1]);
  *fd = ends[0];
  *token = FIXTURE_TOKEN;
  atomic_store(&thermal_token, *token);
  atomic_store(&thermal_fd, *fd);
  return NOTIFY_STATUS_OK;
#endif
}
static uint32_t probe_query(int token, uint64_t *state) {
  if (token != atomic_load(&thermal_token))
    return notify_get_state(token, state);
  atomic_fetch_or(&paths, 2);
#if depot_FAULT_KIND == 2
  (void)state;
  return NOTIFY_STATUS_FAILED;
#else
  *state = 0; /* Actual Rust subscriber must transition from nominal to fail
                 closed. */
  return NOTIFY_STATUS_OK;
#endif
}
static uint32_t probe_cancel(int token) {
  if (token != atomic_load(&thermal_token))
    return notify_cancel(token);
  atomic_fetch_or(&paths, 4);
#if depot_FAULT_KIND <= 2
  return notify_cancel(token);
#else
  return NOTIFY_STATUS_OK; /* Fixture token never registered with notifyd. */
#endif
}
#if depot_FAULT_KIND == 2 || depot_FAULT_KIND == 4
static ssize_t probe_read(int fd, void *buf, size_t count) {
  if (fd != atomic_load(&thermal_fd))
    return read(fd, buf, count);
  atomic_fetch_or(&paths, 8);
#if depot_FAULT_KIND == 4
  errno = EIO;
  return -1;
#else
  /* Rust enters read only AFTER storing the failed initial-query result.
     Without this signal its initial Critical value could mask a later
     erroneous Nominal store, falsely satisfying the failure probe. */
  return read(fd, buf, count);
#endif
}
#endif
#define INTERPOSE(replacement, original)                                       \
  __attribute__((used)) static const struct {                                  \
    const void *r;                                                             \
    const void *o;                                                             \
  } interpose_##original __attribute__((section("__DATA,__interpose"))) = {    \
      (const void *)(uintptr_t)&replacement,                                   \
      (const void *)(uintptr_t)&original}
INTERPOSE(probe_register, notify_register_file_descriptor);
INTERPOSE(probe_query, notify_get_state);
INTERPOSE(probe_cancel, notify_cancel);
#if depot_FAULT_KIND == 2 || depot_FAULT_KIND == 4
INTERPOSE(probe_read, read);
#endif
