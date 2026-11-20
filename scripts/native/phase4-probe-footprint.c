/* Standalone probe support only; full kernel buffers use the active SDK ABI. */
#include <mach/mach.h>
#include <mach/task_info.h>
#include <stdint.h>

int depot_probe_self_footprint(uint64_t *bytes) {
  if (!bytes)
    return -1;
  task_vm_info_data_t info = {0};
  mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
  kern_return_t result =
      task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count);
  if (result != KERN_SUCCESS || count < TASK_VM_INFO_REV1_COUNT)
    return -1;
  *bytes = info.phys_footprint;
  return 0;
}
