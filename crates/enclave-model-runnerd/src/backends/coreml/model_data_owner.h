// Private current-Foundation-span ownership for synchronous model-file writes.
// File/kernel/framework/cache copies and historical backing stores are
// excluded.
#pragma once
#import <Foundation/Foundation.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>

static BOOL scrubCurrentModelData(NSMutableData *data) {
  if (!data)
    return YES;
  @try {
    NSUInteger length = data.length;
    void *bytes = data.mutableBytes;
    if ((!bytes && length != 0) || data.length != length)
      return NO;
    volatile unsigned char *cursor = bytes;
    for (NSUInteger i = 0; i < length; i++)
      cursor[i] = 0;
    atomic_signal_fence(memory_order_seq_cst);
    return YES;
  } @catch (NSException *exception) {
    (void)exception;
    return NO;
  }
}

// Both callers allocate this mutable object with its full zeroed length before
// any copied model byte. Keep a precise strong owner through
// copy/write/finally; this helper retains no borrowed Rust pointer or public
// mutable byte pointer.
static BOOL writeOwnedModelData(NSMutableData *data, const unsigned char *input,
                                size_t length, NSURL *file, NSError **error) {
  __attribute__((objc_precise_lifetime)) NSMutableData *owner = data;
  BOOL written = NO;
  BOOL cleaned = NO;
  @try {
    if (!owner || !input || !length || !file || owner.length != length)
      return NO;
    void *bytes = owner.mutableBytes;
    if (!bytes || owner.length != length)
      return NO;
    medepoty(bytes, input, length);
    written = [owner writeToURL:file options:NSDataWritingAtomic error:error];
  } @finally {
    // Cleanup failures never mask an earlier write exception or overwrite
    // its NSError. Otherwise-successful writes cannot authorize compilation
    // if the current mutable span could not be scrubbed.
    cleaned = scrubCurrentModelData(owner);
  }
  return written && cleaned;
}
