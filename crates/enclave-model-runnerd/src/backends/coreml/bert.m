// Debug-only fixed trained BERT bridge. No production Engine/admission/egress.
// The exact canonical source and ordered compiled lowering are both required.
#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
#import <CoreML/MLModelStructure.h>
#import <CoreML/MLModelStructureNeuralNetwork.h>
#import <CoreML/MLModelStructureNeuralNetworkLayer.h>
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/dispatch.h>
#include <mach/mach.h>
#include <math.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "model_data_owner.h"

@interface EnclaveCoreMLBert : NSObject
@property(nonatomic, strong) MLModel *model;
@property(nonatomic, strong) NSURL *directory;
@end

// mkdir is exclusive: an existing path never becomes this owner's cleanup
// authority. Keep the candidate URL local until a new directory exists.
static BOOL createOwnedDirectory(EnclaveCoreMLBert *owner, NSURL *candidate) {
    const char *path = candidate.fileSystemRepresentation;
    if (!path || mkdir(path, 0700) != 0) return NO;
    owner.directory = candidate;
    return YES;
}
@implementation EnclaveCoreMLBert
- (void)dealloc {
    if (_directory) [NSFileManager.defaultManager removeItemAtURL:_directory error:nil];
}
@end

static uint64_t footprint(void) {
    task_vm_info_data_t info = {0};
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) != KERN_SUCCESS
        || count < TASK_VM_INFO_REV1_COUNT) return 0;
    return info.phys_footprint;
}
static BOOL shape(MLFeatureDescription *feature, NSArray *expected) {
    return feature.type == MLFeatureTypeMultiArray
        && feature.multiArrayConstraint.dataType == MLMultiArrayDataTypeFloat32
        && [feature.multiArrayConstraint.shape isEqualToArray:expected];
}
static BOOL canonicalBytes(const unsigned char *bytes, size_t length) {
    if (!bytes || length != 17222603) return NO;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(bytes, (CC_LONG)length, digest);
    const unsigned char expected[CC_SHA256_DIGEST_LENGTH] = {
        0x90,0x8b,0xeb,0x3a,0x7a,0x15,0x48,0x38,0x0b,0xf6,0xd6,0x15,0x84,0xff,0x9e,0x24,
        0xf2,0x59,0x13,0x51,0x07,0xd9,0x46,0xb9,0xad,0xa4,0x1f,0xa4,0x54,0x53,0x8d,0x91
    };
    return memcmp(digest, expected, sizeof(expected)) == 0;
}

static void expectLayer(NSMutableArray *result, NSString *name, NSString *type,
                        NSArray *inputs, NSString *output) {
    [result addObject:@{@"name":name,@"type":type,@"inputs":inputs,@"outputs":@[output]}];
}

// One specific public-runtime lowering observed on the pinned owned runner.
// Every source LayerNorm becomes ten layers; names alone are insufficient, so
// compare all ordered operation types and edges too. The public metadata does
// not expose reduction axes/arithmetic parameters. Exact source-model SHA256
// below plus independent scalar output comparisons remain mandatory; this is
// not a generic arbitrary-model admission or mathematical equivalence proof.
static void expectNorm(NSMutableArray *result, NSString *name, NSString *input,
                       NSUInteger sourcePosition, NSUInteger ordinal) {
    NSString *suffix = ordinal ? [NSString stringWithFormat:@"_@ssa_version_%lu",(unsigned long)ordinal] : @"";
    NSString *(^value)(NSString *) = ^NSString *(NSString *base) { return [base stringByAppendingString:suffix]; };
    NSString *(^layer)(NSString *) = ^NSString *(NSString *part) {
        return [NSString stringWithFormat:@"%@_%@_%lu",name,part,(unsigned long)sourcePosition];
    };
    expectLayer(result,layer(@"numerator_reduce_mean"),@"reduce",@[input],value(@"reduce_mean"));
    expectLayer(result,layer(@"numerator"),@"elementwise",@[input,value(@"reduce_mean")],value(@"numerator"));
    expectLayer(result,layer(@"denominator_reduce_l2"),@"reduce",@[value(@"numerator")],value(@"reduce_l2"));
    expectLayer(result,layer(@"square_of_denominator"),@"elementwise",@[value(@"reduce_l2"),value(@"reduce_l2")],value(@"square_of_denominator"));
    expectLayer(result,layer(@"denominator"),@"elementwise",@[value(@"square_of_denominator")],value(@"denominator"));
    expectLayer(result,layer(@"numerator_div_denominator"),@"elementwise",@[value(@"numerator"),value(@"denominator")],value(@"numerator_div_denominator"));
    expectLayer(result,layer(@"gamma"),@"load_constant",@[],value(@"gamma"));
    expectLayer(result,layer(@"beta"),@"load_constant",@[],value(@"beta"));
    expectLayer(result,layer(@"numerator_div_denominator_mul_gamma"),@"elementwise",@[value(@"numerator_div_denominator"),value(@"gamma")],value(@"numerator_div_denominator_mul_gamma"));
    // The runtime reuses this layer name for the final beta add; output edges
    // distinguish the two operations, and are checked exactly.
    expectLayer(result,layer(@"numerator_div_denominator_mul_gamma"),@"elementwise",@[value(@"numerator_div_denominator_mul_gamma"),value(@"beta")],name);
}

static NSArray *expectedBertGraph(void) {
    NSMutableArray *result = [NSMutableArray array];
    expectLayer(result,@"token_embedding",@"inner_product",@[@"tokens"],@"token_embedding");
    expectLayer(result,@"position_and_type0",@"load_constant",@[],@"position_and_type0");
    expectLayer(result,@"embedding_sum",@"elementwise",@[@"token_embedding",@"position_and_type0"],@"embedding_sum");
    expectNorm(result,@"embedding_norm",@"embedding_sum",4,0);
    expectLayer(result,@"attention_scale",@"load_constant",@[],@"attention_scale");
    NSString *input = @"embedding_norm";
    for (NSUInteger block=0; block<2; block++) {
        NSString *(^n)(NSString *) = ^NSString *(NSString *part) { return [NSString stringWithFormat:@"block%lu_%@",(unsigned long)block,part]; };
        for (NSString *part in @[@"query",@"key",@"value"]) {
            NSString *base=n(part), *reshape=n([part stringByAppendingString:@"_reshape"]);
            NSString *heads=n([part stringByAppendingString:@"_heads"]);
            expectLayer(result,base,@"inner_product",@[input],base);
            expectLayer(result,reshape,@"reshape",@[base],reshape);
            expectLayer(result,heads,@"transpose",@[reshape],heads);
        }
        expectLayer(result,n(@"scores"),@"batch_matmul",@[n(@"query_heads"),n(@"key_heads")],n(@"scores"));
        expectLayer(result,n(@"scaled_scores"),@"elementwise",@[n(@"scores"),@"attention_scale"],n(@"scaled_scores"));
        expectLayer(result,n(@"probabilities"),@"softmax_nd",@[n(@"scaled_scores")],n(@"probabilities"));
        expectLayer(result,n(@"context"),@"batch_matmul",@[n(@"probabilities"),n(@"value_heads")],n(@"context"));
        expectLayer(result,n(@"context_transpose"),@"transpose",@[n(@"context")],n(@"context_transpose"));
        expectLayer(result,n(@"context_flat"),@"reshape",@[n(@"context_transpose")],n(@"context_flat"));
        expectLayer(result,n(@"attention_out"),@"inner_product",@[n(@"context_flat")],n(@"attention_out"));
        expectLayer(result,n(@"attention_residual"),@"elementwise",@[input,n(@"attention_out")],n(@"attention_residual"));
        expectNorm(result,n(@"attention_norm"),n(@"attention_residual"),block?46:23,block?3:1);
        expectLayer(result,n(@"intermediate"),@"inner_product",@[n(@"attention_norm")],n(@"intermediate"));
        expectLayer(result,n(@"exact_gelu"),@"activation",@[n(@"intermediate")],n(@"exact_gelu"));
        expectLayer(result,n(@"output"),@"inner_product",@[n(@"exact_gelu")],n(@"output"));
        expectLayer(result,n(@"output_residual"),@"elementwise",@[n(@"attention_norm"),n(@"output")],n(@"output_residual"));
        expectNorm(result,n(@"output_norm"),n(@"output_residual"),block?51:28,block?4:2);
        input=n(@"output_norm");
    }
    return result;
}


// Four fixed physical points. Zero is unknown; no point is a stage peak.
void *enclave_coreml_bert_create(const unsigned char *bytes, size_t length,
                                 uint64_t *points, int *status) {
    if (status) *status = -1;
    if (!points || !status) return NULL;
    memset(points, 0, 4 * sizeof(uint64_t));
#ifndef MCPMAC_COREML_BERT_DEVELOPMENT
    (void)bytes; (void)length;
    *status = -90; return NULL;
#else
    if (!canonicalBytes(bytes, length)) { *status = -2; return NULL; }
    @autoreleasepool {
        @try {
            EnclaveCoreMLBert *owner = [EnclaveCoreMLBert new];
            NSFileManager *files = NSFileManager.defaultManager;
            NSURL *base = [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
            NSURL *directory = [base URLByAppendingPathComponent:
                [@"mcpmac-bert-" stringByAppendingString:NSUUID.UUID.UUIDString] isDirectory:YES];
            NSError *error = nil;
            if (!createOwnedDirectory(owner, directory)) { *status=-3; return NULL; }
            NSURL *source = [owner.directory URLByAppendingPathComponent:@"bert8.mlmodel"];
            @autoreleasepool {
                NSMutableData *modelData = [NSMutableData dataWithLength:length];
                if (!writeOwnedModelData(modelData, bytes, length, source, &error)) { *status=-4; return NULL; }
            }
            points[0] = footprint();
            NSURL *temporary = [MLModel compileModelAtURL:source error:&error];
            points[1] = footprint();
            if (!temporary) { *status=-5; return NULL; }
            NSURL *compiled = [owner.directory URLByAppendingPathComponent:@"bert8.mlmodelc" isDirectory:YES];
            if (![files moveItemAtURL:temporary toURL:compiled error:&error]) {
                [files removeItemAtURL:temporary error:nil]; *status=-6; return NULL;
            }
            MLModelConfiguration *configuration = [MLModelConfiguration new];
            configuration.computeUnits = MLComputeUnitsCPUOnly;
            owner.model = [MLModel modelWithContentsOfURL:compiled configuration:configuration error:&error];
            points[2] = footprint();
            if (!owner.model) { *status=-7; return NULL; }
            MLModelDescription *description = owner.model.modelDescription;
            if (description.inputDescriptionsByName.count != 1 || description.outputDescriptionsByName.count != 1
                || !shape(description.inputDescriptionsByName[@"tokens"], @[@8,@1])
                || !shape(description.outputDescriptionsByName[@"block1_output_norm"], @[@8,@128])) {
                *status=-8; return NULL;
            }
            if (@available(macOS 14.4,*)) {
                __block MLModelStructure *structure = nil;
                dispatch_semaphore_t ready = dispatch_semaphore_create(0);
                // A timed-out completion retains only native owner/objects,
                // never the borrowed Rust bytes, status or point buffers.
                EnclaveCoreMLBert *retainedOwner = owner;
                [MLModelStructure loadContentsOfURL:compiled completionHandler:^(MLModelStructure *value,NSError *failure) {
                    (void)retainedOwner;
                    if (!failure) structure=value;
                    dispatch_semaphore_signal(ready);
                }];
                NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5];
                BOOL complete = NO;
                while (deadline.timeIntervalSinceNow > 0) {
                    if (dispatch_semaphore_wait(ready, dispatch_time(DISPATCH_TIME_NOW, 5*NSEC_PER_MSEC)) == 0) {
                        complete=YES; break;
                    }
                    [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                        beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.001]];
                }
                if (!complete || !structure.neuralNetwork || structure.program || structure.pipeline) {
                    *status=-9; return NULL;
                }
                NSArray *expected = expectedBertGraph();
                NSArray<MLModelStructureNeuralNetworkLayer *> *layers = structure.neuralNetwork.layers;
                if (expected.count != 96 || layers.count != expected.count) { *status=-10; return NULL; }
                for (NSUInteger i=0; i<layers.count; i++) {
                    MLModelStructureNeuralNetworkLayer *layer = layers[i];
                    if (!layer.name || !layer.type || !layer.inputNames || !layer.outputNames) {
                        *status=-11; return NULL;
                    }
                    NSDictionary *observed = @{@"name":layer.name,@"type":layer.type,
                        @"inputs":layer.inputNames,@"outputs":layer.outputNames};
                    if (![observed isEqualToDictionary:expected[i]]) { *status=-12; return NULL; }
                }
            } else { *status=-13; return NULL; }
            points[3] = footprint();
            fputs("COREML_BERT_OBSERVED_GRAPH=true layers=96\n",stderr);
            *status=0;
            return (__bridge_retained void *)owner;
        } @catch (NSException *exception) { (void)exception; *status=-14; return NULL; }
    }
#endif
}

#ifdef MCPMAC_COREML_BERT_DEVELOPMENT
// Mutable public access may replace backing storage. Only its current exposed
// span is scrubbed; historical/framework/provider/compute copies are excluded.
static BOOL scrubCurrentBertArray(MLMultiArray *array) {
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

static BOOL bertArrayStrides(MLMultiArray *array, NSArray<NSNumber *> *strides,
                             const void *bytes, NSInteger size, size_t rows, size_t columns,
                             size_t *rowStride, size_t *columnStride) {
    if (!bytes || size < (NSInteger)sizeof(float) || rows == 0 || columns == 0
        || rows > 8 || columns > 128 || array.dataType != MLMultiArrayDataTypeFloat32
        || array.count != (NSInteger)(rows * columns) || array.shape.count != 2
        || array.shape[0].unsignedIntegerValue != rows || array.shape[1].unsignedIntegerValue != columns
        || strides.count != 2 || ((uintptr_t)bytes % _Alignof(float)) != 0) return NO;
    NSInteger row = strides[0].integerValue, column = strides[1].integerValue;
    if (row < 0 || column < 0 || (rows > 1 && row == 0) || (columns > 1 && column == 0)) return NO;
    // Subtract only checked contributions so neither product nor sum overflows.
    size_t remaining = (size_t)size / sizeof(float) - 1;
    if (rows > 1 && (size_t)row > remaining / (rows - 1)) return NO;
    remaining -= (rows - 1) * (size_t)row;
    if (columns > 1 && (size_t)column > remaining / (columns - 1)) return NO;
    *rowStride = (size_t)row; *columnStride = (size_t)column;
    return YES;
}

static int predictCurrentBertArrays(EnclaveCoreMLBert *owner, const uint32_t *tokens,
                                    float *output, MLMultiArray *__strong *inputOwner,
                                    MLMultiArray *__strong *resultOwner) {
    MLModelDescription *description = owner.model.modelDescription;
    if (!shape(description.inputDescriptionsByName[@"tokens"], @[@8,@1])
        || !shape(description.outputDescriptionsByName[@"block1_output_norm"], @[@8,@128])) return -3;
    NSError *error = nil;
    *inputOwner = [[MLMultiArray alloc] initWithShape:@[@8,@1]
        dataType:MLMultiArrayDataTypeFloat32 error:&error];
    MLMultiArray *array = *inputOwner;
    if (!array) return -4;
    __block int status = -4;
    [array getMutableBytesWithHandler:^(void *bytes, NSInteger size, NSArray<NSNumber *> *strides) {
        size_t row = 0, column = 0;
        if (!bertArrayStrides(array, strides, bytes, size, 8, 1, &row, &column)) return;
        float *values = bytes;
        // Every validated token is exactly representable as Float32.
        for (size_t i = 0; i < 8; i++) values[i * row] = (float)tokens[i];
        status = 0;
    }];
    if (status != 0) return status;
    MLDictionaryFeatureProvider *features = [[MLDictionaryFeatureProvider alloc]
        initWithDictionary:@{@"tokens":[MLFeatureValue featureValueWithMultiArray:array]} error:&error];
    if (!features) return -5;
    id<MLFeatureProvider> prediction = [owner.model predictionFromFeatures:features error:&error];
    *resultOwner = [prediction featureValueForName:@"block1_output_norm"].multiArrayValue;
    MLMultiArray *result = *resultOwner;
    if (!result || result.count != 1024 || ![result.shape isEqualToArray:@[@8,@128]]
        || result.dataType != MLMultiArrayDataTypeFloat32) return -6;
    status = -6;
    [result getBytesWithHandler:^(const void *bytes, NSInteger size) {
        size_t row = 0, column = 0;
        if (!bertArrayStrides(result, result.strides, bytes, size, 8, 128, &row, &column)) return;
        const float *values = bytes;
        // Preserve the complete finite precheck: no prefix escapes on a late
        // nonfinite value. The same live callback span supplies the final copy.
        for (size_t i = 0; i < 8; i++) for (size_t j = 0; j < 128; j++) {
            if (!isfinite(values[i * row + j * column])) { status = -7; return; }
        }
        for (size_t i = 0; i < 8; i++) for (size_t j = 0; j < 128; j++) {
            output[i * 128 + j] = values[i * row + j * column];
        }
        status = 0;
    }];
    return status;
}
#endif

int enclave_coreml_bert_predict(void *handle, const uint32_t *tokens, size_t length,
                                 float *output, size_t count, uint64_t *points) {
    if (!points) return -1;
    memset(points, 0, 2 * sizeof(uint64_t));
#ifndef MCPMAC_COREML_BERT_DEVELOPMENT
    (void)handle; (void)tokens; (void)length; (void)output; (void)count;
    return -90;
#else
    if (!handle || !tokens || !output || length != 8 || count != 1024) return -1;
    // Validate every ID before allocating or invoking CoreML; no truncation.
    for (size_t i=0; i<length; i++) if (tokens[i] >= 30522) return -2;
    points[0] = footprint();
    @autoreleasepool {
        MLMultiArray *inputOwner = nil;
        MLMultiArray *resultOwner = nil;
        int status = -8;
        @try {
            EnclaveCoreMLBert *owner = (__bridge EnclaveCoreMLBert *)handle;
            status = predictCurrentBertArrays(owner, tokens, output, &inputOwner, &resultOwner);
        } @catch (NSException *exception) { (void)exception; status = -8; }
        BOOL resultScrubbed = scrubCurrentBertArray(resultOwner);
        BOOL inputScrubbed = scrubCurrentBertArray(inputOwner);
        if ((!resultScrubbed || !inputScrubbed) && status == 0) status = -9;
        if (status != 0) return status;
    }
    points[1] = footprint();
    return 0;
#endif
}

void enclave_coreml_bert_destroy(void *handle, uint64_t *points) {
    if (points) memset(points, 0, 2 * sizeof(uint64_t));
#ifndef MCPMAC_COREML_BERT_DEVELOPMENT
    (void)handle;
#else
    if (!handle) return;
    if (points) points[0] = footprint();
    @autoreleasepool {
        EnclaveCoreMLBert *owner = (__bridge_transfer EnclaveCoreMLBert *)handle;
        owner=nil;
    }
    if (points) points[1] = footprint();
#endif
}

// Executable regression for the exact production ownership helper. It accepts
// no caller-chosen path and touches only its mkdtemp-owned fixture. The hook
// exists only in debug code. A helper pass is not trained-model acceptance.
#ifdef MCPMAC_COREML_BERT_DEVELOPMENT
int enclave_coreml_bert_directory_ownership_check(void) {
    @autoreleasepool {
        NSString *pattern = [NSTemporaryDirectory() stringByAppendingPathComponent:@"mcpmac-bert-owner-XXXXXX"];
        char *temporary = strdup(pattern.fileSystemRepresentation);
        if (!temporary) return -1;
        if (!mkdtemp(temporary)) { free(temporary); return -2; }
        NSURL *root = [NSURL fileURLWithFileSystemRepresentation:temporary isDirectory:YES relativeToURL:nil];
        free(temporary);
        NSFileManager *files = NSFileManager.defaultManager;
        int result = 0;
        @try {
            NSURL *collision = [root URLByAppendingPathComponent:@"existing" isDirectory:YES];
            NSURL *sentinel = [collision URLByAppendingPathComponent:@"sentinel"];
            NSData *content = [@"preserve-existing-owner" dataUsingEncoding:NSUTF8StringEncoding];
            if (mkdir(collision.fileSystemRepresentation, 0700) != 0
                || ![content writeToURL:sentinel atomically:YES]) result=-3;
            if (!result) {
                @autoreleasepool {
                    EnclaveCoreMLBert *owner = [EnclaveCoreMLBert new];
                    if (createOwnedDirectory(owner, collision) || owner.directory) result=-4;
                }
                if (![[NSData dataWithContentsOfURL:sentinel] isEqualToData:content]) result=-5;
            }
            NSURL *existingFile = [root URLByAppendingPathComponent:@"existing-file"];
            if (!result) {
                if (![content writeToURL:existingFile atomically:YES]) result=-6;
                @autoreleasepool {
                    EnclaveCoreMLBert *owner = [EnclaveCoreMLBert new];
                    if (createOwnedDirectory(owner, existingFile) || owner.directory) result=-7;
                }
                if (![[NSData dataWithContentsOfURL:existingFile] isEqualToData:content]) result=-8;
            }
            NSURL *owned = [root URLByAppendingPathComponent:@"owned" isDirectory:YES];
            if (!result) {
                @autoreleasepool {
                    EnclaveCoreMLBert *owner = [EnclaveCoreMLBert new];
                    if (!createOwnedDirectory(owner, owned)) result=-9;
                }
                if ([files fileExistsAtPath:owned.path]) result=-10;
            }
        } @catch (NSException *exception) { (void)exception; result=-11; }
        [files removeItemAtURL:root error:nil];
        return result;
    }
}
#endif
