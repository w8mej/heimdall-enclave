// Test-only crasher binary for FS-705 §5.3.5 fault-injection matrix.
// Never distributed in release builds.

#include <mach/mach.h>
#include <mach/mach_init.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define EXC_MASK_BAD_ACCESS (1 << 1)
#define EXC_MASK_BAD_INSTRUCTION (1 << 2)
#define EXC_MASK_GUARD (1 << 12)
#define MACH_EXCEPTION_CODES 0x80000000
#define EXCEPTION_DEFAULT 1
#if defined(__arm64__) || defined(__aarch64__)
#define THREAD_STATE_NONE 5
#else
#define THREAD_STATE_NONE 13
#endif

static void register_supervisor_port(void) {
  mach_port_t bp;
  task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bp);
  mach_port_t exc_port = MACH_PORT_NULL;
  kern_return_t kr =
      bootstrap_look_up(bp, "com.enterprise.enclave.exception", &exc_port);
  if (kr == KERN_SUCCESS && exc_port != MACH_PORT_NULL) {
    task_set_exception_ports(
        mach_task_self(),
        EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_GUARD,
        exc_port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, THREAD_STATE_NONE);
  }
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: crasher <null|illegal|pac>\n");
    return 1;
  }

  register_supervisor_port();

  if (strcmp(argv[1], "null") == 0) {
    volatile char *p = (volatile char *)0x0;
    // cppcheck-suppress nullPointer
    *p = 42;
  } else if (strcmp(argv[1], "illegal") == 0) {
#if defined(__arm64__) || defined(__aarch64__)
    __asm__ volatile(".inst 0x00000000"); // Arm64 UDF
#else
    __asm__ volatile("ud2");
#endif
  } else if (strcmp(argv[1], "pac") == 0) {
    // Attempt a jump to a tagged pointer with corrupted PAC bits
    void (*bad_fn)(void) = (void (*)(void))(uintptr_t)0x7f00000100002000ULL;
    bad_fn();
  } else {
    fprintf(stderr, "unknown crash mode: %s\n", argv[1]);
    return 2;
  }

  return 0;
}
