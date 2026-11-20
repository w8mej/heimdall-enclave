// Public CoreML API only. Exact model bytes come from the closed Rust exporter.
// Compilation caches/working memory are not claimed to be securely erased.
#import <CoreML/CoreML.h>
#import <CoreML/MLModelStructure.h>
#import <CoreML/MLModelStructureNeuralNetwork.h>
#import <CoreML/MLModelStructureNeuralNetworkLayer.h>
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <math.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include "model_data_owner.h"

@interface EnclaveCoreML : NSObject
@property(nonatomic, strong) MLModel *model;
@property(nonatomic, strong) NSURL *directory;
@property(nonatomic, strong) NSURL *compiled;
@end

// Only exclusive creation establishes cleanup authority. In particular, an
// existing directory, file or symlink must never be adopted on failure.
static BOOL createOwnedDirectory(EnclaveCoreML *owner, NSURL *candidate) {
    const char *path = candidate.fileSystemRepresentation;
    if (!path || mkdir(path, 0700) != 0) return NO;
    owner.directory = candidate;
    return YES;
}
@implementation EnclaveCoreML
- (void)dealloc {
    NSFileManager *fm = NSFileManager.defaultManager;
    if (_compiled) [fm removeItemAtURL:_compiled error:nil];
    if (_directory) [fm removeItemAtURL:_directory error:nil];
}
@end

void *enclave_coreml_create(const unsigned char *bytes, size_t len, int *status) {
    if (status) *status = -1;
    if (!bytes || !len || len > 1048576 || !status) return NULL;
    @autoreleasepool {
        @try {
            EnclaveCoreML *owner = [EnclaveCoreML new];
            NSURL *base = [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
            NSURL *directory = [base URLByAppendingPathComponent:[@"depot-coreml-" stringByAppendingString:NSUUID.UUID.UUIDString] isDirectory:YES];
            NSError *error = nil;
            if (!createOwnedDirectory(owner, directory)) { *status=-2; return NULL; }
            NSURL *file = [owner.directory URLByAppendingPathComponent:@"classifier.mlmodel"];
            @autoreleasepool {
                NSMutableData *modelData = [NSMutableData dataWithLength:len];
                if (!writeOwnedModelData(modelData, bytes, len, file, &error)) { *status=-3; return NULL; }
            }
            owner.compiled = [MLModel compileModelAtURL:file error:&error];
            if (!owner.compiled) { *status=-4; return NULL; }
            MLModelConfiguration *configuration = [MLModelConfiguration new];
            configuration.computeUnits = MLComputeUnitsCPUOnly;
            owner.model = [MLModel modelWithContentsOfURL:owner.compiled configuration:configuration error:&error];
            if (!owner.model) { *status=-5; return NULL; }
            MLModelDescription *description=owner.model.modelDescription;
            MLFeatureDescription *input=description.inputDescriptionsByName[@"input"];
            MLFeatureDescription *output=description.outputDescriptionsByName[@"output"];
            if (description.inputDescriptionsByName.count!=1 || description.outputDescriptionsByName.count!=1
                || input.type!=MLFeatureTypeMultiArray || output.type!=MLFeatureTypeMultiArray
                || input.multiArrayConstraint.shape.count!=1 || output.multiArrayConstraint.shape.count!=1
                || input.multiArrayConstraint.dataType!=MLMultiArrayDataTypeFloat32
                || output.multiArrayConstraint.dataType!=MLMultiArrayDataTypeFloat32) { *status=-8;return NULL; }
            // Observe the framework's actual compiled graph before prediction.
            // Unknown program/pipeline/nested/custom structures never fall back
            // to a publisher-declared list or merely the generated source graph.
            if (@available(macOS 14.4,*)) {
                __block MLModelStructure *structure=nil;
                dispatch_semaphore_t ready=dispatch_semaphore_create(0);
                EnclaveCoreML *retainedOwner=owner;
                [MLModelStructure loadContentsOfURL:owner.compiled completionHandler:^(MLModelStructure *value,NSError *failure){
                    (void)retainedOwner;
                    if (!failure) structure=value;
                    dispatch_semaphore_signal(ready);
                }];
                NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:5];
                BOOL complete=NO;
                while (deadline.timeIntervalSinceNow>0) {
                    if (dispatch_semaphore_wait(ready,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_MSEC))==0) { complete=YES;break; }
                    [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.001]];
                }
                if (!complete) { *status=-11;return NULL; }
                if (!structure) { *status=-10;return NULL; }
                if (!structure.neuralNetwork || structure.program || structure.pipeline) { *status=-12;return NULL; }
                NSArray<MLModelStructureNeuralNetworkLayer *> *layers=structure.neuralNetwork.layers;
                if (layers.count!=1) { *status=-13;return NULL; }
                MLModelStructureNeuralNetworkLayer *layer=layers.firstObject;
                // MLModelStructure uses the public runtime spelling, distinct
                // from the Model protobuf's `innerProduct` field spelling.
                if (![layer.type isEqualToString:@"inner_product"]
                    || ![layer.name isEqualToString:@"enclave_dense_classifier"]
                    || ![layer.inputNames isEqualToArray:@[@"input"]]
                    || ![layer.outputNames isEqualToArray:@[@"output"]]) {
                    // Fixed generated graph only; operation type is safe metadata.
                    fprintf(stderr,"COREML_STRUCTURE_REJECTED type=%.64s\n",layer.type.UTF8String ?: "nil");
                    *status=-13;return NULL;
                }
                fputs("COREML_OBSERVED_GRAPH=true layers=1 type=inner_product\n",stderr);
            } else { *status=-9;return NULL; }
            *status = 0;
            return (__bridge_retained void *)owner;
        } @catch (NSException *exception) { *status=-6; return NULL; }
    }
}

// Public callback pointers never escape their access block. Mutable access can
// change the backing store: only the currently exposed span is scrubbed here;
// previous framework copies, caches and compute intermediates remain excluded.
static BOOL scrubCurrentArray(MLMultiArray *array) {
    if (!array) return YES;
    @try {
        __block BOOL scrubbed = NO;
        [array getMutableBytesWithHandler:^(void *bytes, NSInteger size, NSArray<NSNumber *> *strides) {
            (void)strides;
            if (size < 0 || (!bytes && size != 0)) return;
            volatile unsigned char *cursor = (volatile unsigned char *)bytes;
            for (NSInteger i = 0; i < size; i++) cursor[i] = 0;
            atomic_signal_fence(memory_order_seq_cst);
            scrubbed = YES;
        }];
        return scrubbed;
    } @catch (NSException *exception) { (void)exception; return NO; }
}

// The admitted classifier has one-dimensional Float32 features and outputs.
// Check the actual callback span and strides before any raw scalar access.
static BOOL floatArrayStride(MLMultiArray *array, NSArray<NSNumber *> *strides,
                             const void *bytes, NSInteger size, size_t count, size_t *stride) {
    if (!bytes || size < (NSInteger)sizeof(float) || count == 0
        || array.dataType != MLMultiArrayDataTypeFloat32
        || array.count != (NSInteger)count || array.shape.count != 1
        || array.shape.firstObject.unsignedIntegerValue != count || strides.count != 1
        || ((uintptr_t)bytes % _Alignof(float)) != 0) return NO;
    NSInteger step = strides.firstObject.integerValue;
    size_t capacity = (size_t)size / sizeof(float);
    if (step <= 0 || (count > 1 && (size_t)step > (capacity - 1) / (count - 1))) return NO;
    *stride = (size_t)step;
    return YES;
}

static int predictCurrentArrays(EnclaveCoreML *owner, const float *input, size_t len,
                                float *output, size_t count, int *phase,
                                MLMultiArray *__strong *inputOwner,
                                MLMultiArray *__strong *resultOwner) {
    MLFeatureDescription *inputDescription=owner.model.modelDescription.inputDescriptionsByName[@"input"];
    MLFeatureDescription *outputDescription=owner.model.modelDescription.outputDescriptionsByName[@"output"];
    if (inputDescription.multiArrayConstraint.shape.firstObject.unsignedIntegerValue!=len
        || outputDescription.multiArrayConstraint.shape.firstObject.unsignedIntegerValue!=count) return -8;
    *phase=1;
    NSError *error = nil;
    *inputOwner = [[MLMultiArray alloc] initWithShape:@[@(len)] dataType:MLMultiArrayDataTypeFloat32 error:&error];
    MLMultiArray *array = *inputOwner;
    if (!array) return -2;
    __block int status = -2;
    [array getMutableBytesWithHandler:^(void *bytes, NSInteger size, NSArray<NSNumber *> *strides) {
        size_t stride = 0;
        if (!floatArrayStride(array, strides, bytes, size, len, &stride)) return;
        float *values = (float *)bytes;
        status = 0;
        for (size_t i=0;i<len;i++) {
            if (!isfinite(input[i])) { status = -3; return; }
            values[i * stride] = input[i];
        }
    }];
    if (status != 0) return status;
    *phase=2;
    MLDictionaryFeatureProvider *features = [[MLDictionaryFeatureProvider alloc] initWithDictionary:@{@"input":[MLFeatureValue featureValueWithMultiArray:array]} error:&error];
    if (!features) return -4;
    *phase=3;
    id<MLFeatureProvider> prediction = [owner.model predictionFromFeatures:features error:&error];
    *resultOwner = [prediction featureValueForName:@"output"].multiArrayValue;
    MLMultiArray *result = *resultOwner;
    if (!result || result.count != (NSInteger)count) return -5;
    *phase=4;
    status = -5;
    [result getBytesWithHandler:^(const void *bytes, NSInteger size) {
        size_t stride = 0;
        if (!floatArrayStride(result, result.strides, bytes, size, count, &stride)) return;
        const float *values = (const float *)bytes;
        status = 0;
        for (size_t i=0;i<count;i++) {
            float value = values[i * stride];
            if (!isfinite(value)) { status = -6; return; }
            output[i] = value;
        }
    }];
    return status;
}

int enclave_coreml_predict(void *handle, const float *input, size_t len, float *output, size_t count) {
    if (!handle || !input || !output || !len || len > 256 || count < 2 || count > 256) return -1;
    @autoreleasepool {
        int phase=0;
        int status = -1;
        // Strong owners exist before the first private write and survive all
        // early returns and caught exceptions until both cleanup attempts end.
        MLMultiArray *inputOwner = nil;
        MLMultiArray *resultOwner = nil;
        @try {
            EnclaveCoreML *owner = (__bridge EnclaveCoreML *)handle;
            status = predictCurrentArrays(owner, input, len, output, count,
                                           &phase, &inputOwner, &resultOwner);
        } @catch (NSException *exception) { (void)exception; status = -70-phase; }
        BOOL resultScrubbed = scrubCurrentArray(resultOwner);
        BOOL inputScrubbed = scrubCurrentArray(inputOwner);
        // Keep existing prediction failures; never release success if either
        // public current-buffer cleanup refuses or throws. Rust rejects -7.
        if ((!resultScrubbed || !inputScrubbed) && status == 0) status = -7;
        return status;
    }
}

void enclave_coreml_destroy(void *handle) {
    if (handle) { @autoreleasepool { EnclaveCoreML *owner = (__bridge_transfer EnclaveCoreML *)handle; (void)owner; } }
}
