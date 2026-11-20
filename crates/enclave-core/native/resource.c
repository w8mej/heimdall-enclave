/* Keep kernel output buffers in the SDK's ABI, never a handwritten prefix. */
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/resource.h>

int depot_current_footprint(uint64_t *bytes) {
  task_vm_info_data_t info = {0};
  mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
  kern_return_t kr =
      task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count);
  if (kr != KERN_SUCCESS || count < TASK_VM_INFO_REV1_COUNT)
    return -1;
  *bytes = info.phys_footprint;
  return 0;
}

int depot_pid_footprint(int pid, uint64_t *bytes) {
  struct rusage_info_v4 info = {0};
  if (pid <= 0 ||
      proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&info) != 0)
    return -1;
  *bytes = info.ri_phys_footprint;
  return 0;
}
