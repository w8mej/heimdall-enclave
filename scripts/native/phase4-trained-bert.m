// Standalone development probe, not production model admission or a cap waiver.
// Compile with: clang -fobjc-arc -framework Foundation -framework CoreML ...
#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
#import <CoreML/MLModelStructure.h>
#import <CoreML/MLModelStructureNeuralNetwork.h>
#import <CoreML/MLModelStructureNeuralNetworkLayer.h>
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/dispatch.h>
#include <mach/mach.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

static atomic_bool sampling;
static uint64_t footprintMax, footprintSamples, footprintUnknown;

static void sampleFootprint(void) {
    task_vm_info_data_t info = {0};
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS
        && count >= TASK_VM_INFO_REV1_COUNT) {
        if (info.phys_footprint > footprintMax) footprintMax = info.phys_footprint;
        footprintSamples++;
    } else footprintUnknown++;
}

static void *sampleThread(void *ignored) {
    (void)ignored;
    do { sampleFootprint(); usleep(5000); } while (atomic_load(&sampling));
    return NULL;
}

static void emit(NSDictionary *record) {
    NSData *bytes = [NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingPrettyPrinted error:nil];
    if (bytes) { fwrite(bytes.bytes, 1, bytes.length, stdout); fputc('\n', stdout); fflush(stdout); }
}

static NSString *digest(NSData *bytes) {
    unsigned char output[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(bytes.bytes, (CC_LONG)bytes.length, output);
    NSMutableString *result = [NSMutableString string];
    for (size_t i=0; i<sizeof(output); i++) [result appendFormat:@"%02x",output[i]];
    return result;
}

static BOOL shape(MLFeatureDescription *feature, NSArray *expected) {
    return feature.type == MLFeatureTypeMultiArray
        && feature.multiArrayConstraint.dataType == MLMultiArrayDataTypeFloat32
        && [feature.multiArrayConstraint.shape isEqualToArray:expected];
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

static NSDictionary *run(NSString *directory) {
    NSFileManager *manager = NSFileManager.defaultManager;
    NSString *modelPath = [directory stringByAppendingPathComponent:@"bert8.mlmodel"];
    NSString *probePath = [directory stringByAppendingPathComponent:@"probe.json"];
    NSError *error = nil;
    NSDictionary *modelAttributes = [manager attributesOfItemAtPath:modelPath error:&error];
    NSDictionary *probeAttributes = [manager attributesOfItemAtPath:probePath error:&error];
    if (![modelAttributes[NSFileType] isEqualToString:NSFileTypeRegular]
        || ![probeAttributes[NSFileType] isEqualToString:NSFileTypeRegular]
        || [modelAttributes[NSFileSize] unsignedLongLongValue] > 20000000
        || [probeAttributes[NSFileSize] unsignedLongLongValue] > 1048576)
        return @{@"status":@"FAIL",@"stage":@"bounded-input-files"};
    NSData *modelBytes = [NSData dataWithContentsOfFile:modelPath options:0 error:&error];
    NSData *probeBytes = [NSData dataWithContentsOfFile:probePath options:0 error:&error];
    NSDictionary *probe = probeBytes ? [NSJSONSerialization JSONObjectWithData:probeBytes options:0 error:&error] : nil;
    if (![probe isKindOfClass:NSDictionary.class] || !modelBytes
        || ![digest(modelBytes) isEqualToString:probe[@"model_sha256"]]
        || ![digest(modelBytes) isEqualToString:@"908beb3a7a1548380bf6d61584ff9e24f259135107d946b9ada41fa454538d91"]
        || ![probe[@"checkpoint_sha256"] isEqualToString:@"7fb69ad9f6866d8983183c930e33828f326470bf6ad8bbb2ad4ed957a92e9414"]
        || ![probe[@"output_name"] isEqualToString:@"block1_output_norm"]
        || ![probe[@"cases"] isKindOfClass:NSArray.class] || [probe[@"cases"] count] != 2)
        return @{@"status":@"FAIL",@"stage":@"probe-metadata"};
    NSString *compiledOwned = [directory stringByAppendingPathComponent:@"compiled-owned.mlmodelc"];
    if ([manager fileExistsAtPath:compiledOwned])
        return @{@"status":@"FAIL",@"stage":@"prior-compiled-artifact-preserved"};
    CFAbsoluteTime started = CFAbsoluteTimeGetCurrent();
    NSURL *temporary = [MLModel compileModelAtURL:[NSURL fileURLWithPath:modelPath] error:&error];
    if (!temporary) return @{@"status":@"FAIL",@"stage":@"compile",@"error":error.description ?: @"unknown"};
    NSURL *compiled = [NSURL fileURLWithPath:compiledOwned isDirectory:YES];
    if (![manager moveItemAtURL:temporary toURL:compiled error:&error]) {
        [manager removeItemAtURL:temporary error:nil];
        return @{@"status":@"FAIL",@"stage":@"retain-owned-compiled",@"error":error.description ?: @"unknown"};
    }
    MLModelConfiguration *configuration = [MLModelConfiguration new];
    configuration.computeUnits = MLComputeUnitsCPUOnly;
    MLModel *model = [MLModel modelWithContentsOfURL:compiled configuration:configuration error:&error];
    if (!model) return @{@"status":@"FAIL",@"stage":@"load",@"error":error.description ?: @"unknown"};
    MLModelDescription *description = model.modelDescription;
    if (description.inputDescriptionsByName.count != 1 || description.outputDescriptionsByName.count != 1
        || !shape(description.inputDescriptionsByName[@"tokens"], @[@8,@1])
        || !shape(description.outputDescriptionsByName[@"block1_output_norm"], @[@8,@128]))
        return @{@"status":@"FAIL",@"stage":@"feature-shape"};
    NSMutableArray *observed = [NSMutableArray array];
    if (@available(macOS 14.4,*)) {
        __block MLModelStructure *structure = nil;
        dispatch_semaphore_t ready = dispatch_semaphore_create(0);
        [MLModelStructure loadContentsOfURL:compiled completionHandler:^(MLModelStructure *value,NSError *failure) {
            if (!failure) structure=value;
            dispatch_semaphore_signal(ready);
        }];
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5];
        BOOL complete = NO;
        while (deadline.timeIntervalSinceNow > 0) {
            if (dispatch_semaphore_wait(ready, dispatch_time(DISPATCH_TIME_NOW, 5*NSEC_PER_MSEC)) == 0) { complete=YES; break; }
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.001]];
        }
        if (!complete || !structure.neuralNetwork || structure.program || structure.pipeline)
            return @{@"status":@"FAIL",@"stage":@"observed-graph-kind-or-timeout"};
        NSArray *expected = expectedBertGraph();
        NSArray<MLModelStructureNeuralNetworkLayer *> *layers = structure.neuralNetwork.layers;
        if (layers.count > 512)
            return @{@"status":@"FAIL",@"stage":@"observed-graph-bound",@"count":@(layers.count)};
        // Preserve the actual compiled graph even when its lowering does not
        // match the source graph. This diagnostic cannot authorize prediction.
        for (MLModelStructureNeuralNetworkLayer *layer in layers) {
            if (!layer.name || !layer.type || !layer.inputNames || !layer.outputNames)
                return @{@"status":@"FAIL",@"stage":@"observed-graph-missing-fields"};
            [observed addObject:@{@"name":layer.name,@"type":layer.type,
                                 @"inputs":layer.inputNames,@"outputs":layer.outputNames}];
        }
        if (expected.count != 96 || layers.count != expected.count)
            return @{@"status":@"FAIL",@"stage":@"observed-layer-count",@"count":@(layers.count),
                     @"observed_graph":observed};
        for (NSUInteger i=0; i<observed.count; i++)
            if (![observed[i] isEqualToDictionary:expected[i]])
                return @{@"status":@"FAIL",@"stage":@"observed-lowering-mismatch",@"index":@(i),
                         @"expected_layer":expected[i],@"observed_graph":observed};
    } else return @{@"status":@"FAIL",@"stage":@"graph-observation-unavailable"};
    NSMutableArray *outcomes = [NSMutableArray array];
    NSMutableArray<NSArray *> *vectors = [NSMutableArray array];
    for (NSDictionary *testCase in probe[@"cases"]) {
        NSArray *tokens = testCase[@"token_ids"], *expected = testCase[@"expected"];
        if (![tokens isKindOfClass:NSArray.class] || tokens.count != 8
            || ![expected isKindOfClass:NSArray.class] || expected.count != 1024)
            return @{@"status":@"FAIL",@"stage":@"case-shape"};
        MLMultiArray *array = [[MLMultiArray alloc] initWithShape:@[@8,@1] dataType:MLMultiArrayDataTypeFloat32 error:&error];
        if (!array) return @{@"status":@"FAIL",@"stage":@"input-allocation"};
        for (NSUInteger i=0; i<8; i++) {
            if (![tokens[i] isKindOfClass:NSNumber.class]) return @{@"status":@"FAIL",@"stage":@"token-type"};
            double value = [tokens[i] doubleValue];
            if (!isfinite(value) || floor(value) != value || value < 0 || value >= 30522)
                return @{@"status":@"FAIL",@"stage":@"token-bound"};
            array[i] = @(value);
        }
        MLDictionaryFeatureProvider *features = [[MLDictionaryFeatureProvider alloc]
            initWithDictionary:@{@"tokens":[MLFeatureValue featureValueWithMultiArray:array]} error:&error];
        CFAbsoluteTime predictionStart = CFAbsoluteTimeGetCurrent();
        id<MLFeatureProvider> prediction = [model predictionFromFeatures:features error:&error];
        double duration = CFAbsoluteTimeGetCurrent() - predictionStart;
        MLMultiArray *values = [prediction featureValueForName:@"block1_output_norm"].multiArrayValue;
        if (!values || values.count != 1024 || ![values.shape isEqualToArray:@[@8,@128]])
            return @{@"status":@"FAIL",@"stage":@"prediction-shape",@"error":error.description ?: @"unknown"};
        double maximum = 0;
        NSMutableArray *vector = [NSMutableArray arrayWithCapacity:1024];
        for (NSUInteger i=0; i<1024; i++) {
            if (![expected[i] isKindOfClass:NSNumber.class]) return @{@"status":@"FAIL",@"stage":@"reference-type"};
            double reference = [expected[i] doubleValue], actual = [values[i] doubleValue];
            double delta = fabs(reference-actual);
            if (!isfinite(reference) || !isfinite(actual))
                return @{@"status":@"FAIL",@"stage":@"nonfinite-output",@"index":@(i)};
            if (delta > 0.002 + 0.002*fabs(reference))
                return @{@"status":@"FAIL",@"stage":@"reference-output",@"index":@(i),
                         @"expected":@(reference),@"actual":@(actual),@"observed_graph":observed};
            maximum = fmax(maximum,delta);
            [vector addObject:@(actual)];
        }
        [vectors addObject:vector];
        [outcomes addObject:@{@"token_ids":tokens,@"prediction_seconds":@(duration),@"max_absolute_error":@(maximum),@"compared_values":@1024}];
    }
    double changed = 0;
    for (NSUInteger i=0; i<1024; i++) changed=fmax(changed,fabs([vectors[0][i] doubleValue]-[vectors[1][i] doubleValue]));
    if (changed < 0.001) return @{@"status":@"FAIL",@"stage":@"input-sensitivity"};
    return @{@"status":@"PASS_BOUNDED_TRAINED_ENCODER",@"trained_checkpoint_executed":@YES,
             @"model_sha256":probe[@"model_sha256"],@"checkpoint_sha256":probe[@"checkpoint_sha256"],
             @"compute_units":@"CPUOnly",@"observed_graph":observed,@"cases":outcomes,
             @"observed_lowering_exact":@YES,
             @"graph_observation_limit":@"96 exact ordered public-runtime layer types/names/edges for this SHA-pinned model. Numeric arithmetic/reduction parameters are not exposed; independent1024-value comparisons on2inputs are required, not general equivalence or admission.",
             @"input_difference_max":@(changed),@"elapsed_seconds":@(CFAbsoluteTimeGetCurrent()-started),
             @"full_model_gate_accepted":@NO,@"resource_acceptance":@NO,@"production_adapter_wired":@NO};
}

int main(int argc, const char **argv) {
    if (argc != 2) { fputs("usage: phase4-trained-bert PROBE_DIRECTORY\n",stderr); return 2; }
    @autoreleasepool {
        pthread_t sampler;
        atomic_store(&sampling, true);
        if (pthread_create(&sampler,NULL,sampleThread,NULL) != 0) return 2;
        NSMutableDictionary *result;
        @try { result = [run([NSString stringWithUTF8String:argv[1]]) mutableCopy]; }
        @catch (NSException *exception) { result=[@{@"status":@"FAIL",@"stage":@"native-exception",@"exception":exception.name} mutableCopy]; }
        atomic_store(&sampling, false);
        pthread_join(sampler,NULL);
        result[@"sampled_max_physical_footprint_bytes"] = @(footprintMax);
        result[@"physical_footprint_samples"] = @(footprintSamples);
        result[@"physical_footprint_unknown_samples"] = @(footprintUnknown);
        result[@"sampled_48MiB_cap_exceeded"] = @(footprintMax > 48ull*1024*1024);
        result[@"sampling_limit"] = @"Self TASK_VM_INFO.phys_footprint every5ms; not an independent observer, guaranteed peak or complete child/cache accounting.";
        emit(result);
        return [result[@"status"] isEqualToString:@"PASS_BOUNDED_TRAINED_ENCODER"] ? 0 : 1;
    }
}
