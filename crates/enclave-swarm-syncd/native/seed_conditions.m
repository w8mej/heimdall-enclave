// Read-only SDK observations. No configuration, power or networking mutation.
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <IOKit/ps/IOPowerSources.h>
#import <dispatch/dispatch.h>
#include <stdint.h>
// bit0 AC, bit1 unmetered, bit2 thermal nominal, bit3 low power.
// Failure/timeout returns -1; callers must refuse seeding.
int mcpmac_seed_conditions(uint32_t *flags) {
    if (!flags) return -1;
    @autoreleasepool {
        CFTypeRef info = IOPSCopyPowerSourcesInfo();
        if (!info) return -1;
        CFStringRef source = IOPSGetProvidingPowerSourceType(info);
        if (!source) { CFRelease(info); return -1; }
        BOOL ac = CFEqual(source, CFSTR(kIOPMACPowerKey));
        CFRelease(info);
        NSProcessInfo *process = [NSProcessInfo processInfo];
        if (![process respondsToSelector:@selector(thermalState)] ||
            ![process respondsToSelector:@selector(isLowPowerModeEnabled)]) return -1;
        BOOL nominal = process.thermalState == NSProcessInfoThermalStateNominal;
        BOOL low = process.isLowPowerModeEnabled;
        nw_path_monitor_t monitor = nw_path_monitor_create();
        if (!monitor) return -1;
        dispatch_queue_t queue = dispatch_queue_create("internal.cas.seed-observation", DISPATCH_QUEUE_SERIAL);
        dispatch_semaphore_t ready = dispatch_semaphore_create(0);
        __block BOOL observed = NO;
        __block BOOL unmetered = NO;
        nw_path_monitor_set_queue(monitor, queue);
        nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
            unmetered = nw_path_get_status(path) == nw_path_status_satisfied &&
                !nw_path_is_expensive(path) && !nw_path_is_constrained(path);
            observed = YES;
            dispatch_semaphore_signal(ready);
        });
        nw_path_monitor_start(monitor);
        long timed_out = dispatch_semaphore_wait(ready, dispatch_time(DISPATCH_TIME_NOW, 500 * NSEC_PER_MSEC));
        nw_path_monitor_cancel(monitor);
        // Drain serial callbacks before reading captured values and releasing.
        dispatch_sync(queue, ^{});
        if (timed_out || !observed) return -1;
        *flags = (ac ? 1u : 0u) | (unmetered ? 2u : 0u) | (nominal ? 4u : 0u) | (low ? 8u : 0u);
        return 0;
    }
}
