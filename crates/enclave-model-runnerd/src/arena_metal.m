#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include <string.h>
#include <mach/mach_time.h>
#include <stdatomic.h>

void* metal_device_create(void) {
    @autoreleasepool {
        id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
        if (!dev) return NULL;
        return (__bridge_retained void*)dev;
    }
}

void metal_device_destroy(void* dev) {
    if (dev) {
        CFRelease((CFTypeRef)dev);
    }
}

void* metal_heap_create(void* dev_ptr, size_t size) {
    if (!dev_ptr || size == 0) return NULL;
    @autoreleasepool {
        id<MTLDevice> dev = (__bridge id<MTLDevice>)dev_ptr;
        MTLHeapDescriptor *desc = [MTLHeapDescriptor new];
        desc.size = size;
        desc.storageMode = MTLStorageModeShared;
        id<MTLHeap> heap = [dev newHeapWithDescriptor:desc];
        if (!heap) return NULL;
        return (__bridge_retained void*)heap;
    }
}

void metal_heap_destroy(void* heap) {
    if (heap) {
        CFRelease((CFTypeRef)heap);
    }
}

void* metal_buffer_create(void* heap_ptr, size_t size) {
    if (!heap_ptr || size == 0) return NULL;
    @autoreleasepool {
        id<MTLHeap> heap = (__bridge id<MTLHeap>)heap_ptr;
        id<MTLBuffer> buf = [heap newBufferWithLength:size options:MTLResourceStorageModeShared];
        if (!buf) return NULL;
        return (__bridge_retained void*)buf;
    }
}

void* metal_buffer_contents(void* buf_ptr) {
    if (!buf_ptr) return NULL;
    id<MTLBuffer> buf = (__bridge id<MTLBuffer>)buf_ptr;
    return buf.contents;
}

size_t metal_buffer_length(void* buf_ptr) {
    if (!buf_ptr) return 0;
    id<MTLBuffer> buf = (__bridge id<MTLBuffer>)buf_ptr;
    return buf.length;
}

void metal_buffer_destroy(void* buf) {
    if (buf) {
        CFRelease((CFTypeRef)buf);
    }
}

void* metal_queue_create(void* dev_ptr) {
    if (!dev_ptr) return NULL;
    @autoreleasepool {
        id<MTLDevice> dev = (__bridge id<MTLDevice>)dev_ptr;
        id<MTLCommandQueue> q = [dev newCommandQueue];
        if (!q) return NULL;
        return (__bridge_retained void*)q;
    }
}

void metal_queue_destroy(void* q) {
    if (q) {
        CFRelease((CFTypeRef)q);
    }
}

void* metal_shared_event_create(void* dev_ptr) {
    if (!dev_ptr) return NULL;
    @autoreleasepool {
        id<MTLDevice> dev = (__bridge id<MTLDevice>)dev_ptr;
        id<MTLSharedEvent> ev = [dev newSharedEvent];
        if (!ev) return NULL;
        return (__bridge_retained void*)ev;
    }
}

void metal_shared_event_destroy(void* ev) {
    if (ev) {
        CFRelease((CFTypeRef)ev);
    }
}

uint64_t metal_wipe_buffer(
    void* queue_ptr,
    void* event_ptr,
    void* buffer_ptr,
    size_t canary_offset,
    size_t canary_len,
    uint64_t *out_elapsed_us
) {
    if (!queue_ptr || !buffer_ptr) {
        return (uint64_t)-1;
    }
    
    id<MTLCommandQueue> queue = (__bridge id<MTLCommandQueue>)queue_ptr;
    id<MTLSharedEvent> event = (__bridge id<MTLSharedEvent>)event_ptr;
    id<MTLBuffer> buffer = (__bridge id<MTLBuffer>)buffer_ptr;
    
    size_t buf_len = buffer.length;
    uint8_t *contents = (uint8_t *)buffer.contents;
    if (!contents) return (uint64_t)-1;
    
    uint64_t t0 = mach_absolute_time();
    
    @autoreleasepool {
        // 1. waitUntilCompleted & blit fillBuffer(0)
        id<MTLCommandBuffer> cmdBuf = [queue commandBuffer];
        id<MTLBlitCommandEncoder> blit = [cmdBuf blitCommandEncoder];
        if (!cmdBuf || !blit) return UINT64_MAX;
        [blit fillBuffer:buffer range:NSMakeRange(0, buf_len) value:0];
        [blit endEncoding];
        
        static _Atomic uint64_t s_event_counter = 1;
        if (event) {
            [cmdBuf encodeSignalEvent:event value:atomic_fetch_add(&s_event_counter, 1)];
        }
        [cmdBuf commit];
        [cmdBuf waitUntilCompleted];
        
        // 2. CPU explicit zeroization (memset_s / explicit_bzero)
        if (memset_s(contents, buf_len, 0, buf_len) != 0 || cmdBuf.status != MTLCommandBufferStatusCompleted) return UINT64_MAX;
        
        // 3. Memory fence
        __sync_synchronize();
    }
    
    // 4. Verify every byte of both scratch and the reserved canary, not a sample.
    uint64_t residual = 0;
    for (size_t i = 0; i < buf_len; i++) {
        if (((volatile uint8_t *)contents)[i] != 0) residual++;
    }

    uint64_t t1 = mach_absolute_time();
    mach_timebase_info_data_t tb = {0, 0};
    if (mach_timebase_info(&tb) != KERN_SUCCESS || tb.denom == 0) return UINT64_MAX;
    if (out_elapsed_us) {
        *out_elapsed_us = (uint64_t)((double)(t1 - t0) * tb.numer / tb.denom / 1000.0);
    }
    
    return residual;
}
