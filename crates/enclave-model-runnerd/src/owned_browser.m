// Real WebKit, limited to an in-memory owned document and a nonpersistent store.
#import <AppKit/AppKit.h>
#import <WebKit/WebKit.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// A reserved, never-fetched origin for the built-in development document. The
// matching Rust command guard checks WebKit's actual committed location.
static NSString *const OwnedDocumentURL = @"https://depot-owned.invalid/";

@interface EnclaveOwnedWebKit : NSObject<WKNavigationDelegate, WKUIDelegate>
@property(nonatomic,strong) WKWebView *view;
@property(nonatomic,strong) NSURL *directory;
@property(nonatomic,strong) WKContentRuleListStore *ruleStore;
@property(nonatomic,assign) BOOL loaded;
@property(nonatomic,assign) BOOL failed;
@end

// mkdir is exclusive and refuses an existing final-component directory, file
// or symlink. Cleanup authority is adopted only after this owner created the
// directory; a failed creation must never remove another owner's path.
static BOOL createOwnedDirectory(EnclaveOwnedWebKit *owner, NSURL *candidate) {
    const char *path = candidate.fileSystemRepresentation;
    if (!path || mkdir(path, 0700) != 0) return NO;
    owner.directory = candidate;
    return YES;
}

@implementation EnclaveOwnedWebKit
- (void)dealloc { if (_directory) [NSFileManager.defaultManager removeItemAtURL:_directory error:nil]; }
- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)action decisionHandler:(void (^)(WKNavigationActionPolicy))handler {
    NSString *url = action.request.URL.absoluteString;
    BOOL allowed = !self.loaded && ([url isEqualToString:OwnedDocumentURL]
        || [url isEqualToString:@"about:blank"]);
    handler(allowed ? WKNavigationActionPolicyAllow : WKNavigationActionPolicyCancel);
}
- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation { self.loaded=YES; }
- (void)webView:(WKWebView *)webView didFailNavigation:(WKNavigation *)navigation withError:(NSError *)error { self.failed=YES; }
- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error { self.failed=YES; }
- (void)webViewWebContentProcessDidTerminate:(WKWebView *)webView { self.failed=YES; }
@end

static BOOL pump_until(BOOL (^ready)(void), NSTimeInterval seconds) {
    NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:seconds];
    while (!ready() && deadline.timeIntervalSinceNow>0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.005]];
    }
    return ready();
}

void *enclave_webkit_create(int *status) {
    if (status) *status=-1;
    if (!status || !NSThread.isMainThread) return NULL;
    @autoreleasepool { @try {
        [NSApplication sharedApplication];
        EnclaveOwnedWebKit *owner=[EnclaveOwnedWebKit new];
        NSURL *directory=[[NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES] URLByAppendingPathComponent:[@"depot-webkit-" stringByAppendingString:NSUUID.UUID.UUIDString] isDirectory:YES];
        if (!createOwnedDirectory(owner,directory)) { *status=-2;return NULL; }
        owner.ruleStore=[WKContentRuleListStore storeWithURL:owner.directory];
        WKWebViewConfiguration *config=[WKWebViewConfiguration new];
        config.websiteDataStore=WKWebsiteDataStore.nonPersistentDataStore;
        config.processPool=[WKProcessPool new];
        config.preferences.javaScriptCanOpenWindowsAutomatically=NO;
        __block BOOL rulesDone=NO;
        __block WKContentRuleList *rules=nil;
        [owner.ruleStore compileContentRuleListForIdentifier:@"depotOwnedDenyNetworkV1" encodedContentRuleList:@"[{\"trigger\":{\"url-filter\":\".*\"},\"action\":{\"type\":\"block\"}}]" completionHandler:^(WKContentRuleList *list,NSError *error){rules=list;rulesDone=YES;}];
        if (!pump_until(^BOOL{return rulesDone;},5) || !rules) { *status=-2;return NULL; }
        [config.userContentController addContentRuleList:rules];
        owner.view=[[WKWebView alloc] initWithFrame:NSMakeRect(0,0,1024,768) configuration:config];
        owner.view.navigationDelegate=owner;
        owner.view.UIDelegate=owner;
        NSString *html=
            @"<!doctype html><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'\">"
            @"<title>depot owned offline document</title><style>body{margin:20px}button,input{display:block;width:200px;height:40px;margin:20px}</style>"
            @"<button id='increment' onclick='bump()'>Increment</button><output id='count'>0</output><input id='entry' type='text'>"
            @"<button id='nested-increment' onclick='bump()'><span id='nested-hit' style='display:block;height:100%;line-height:32px'>Nested increment</span></button>"
            @"<section id='delete-repo'><button id='forbidden-child' onclick='bump()'>Forbidden descendant</button></section>"
            @"<div style='position:relative;width:200px;height:40px;margin:20px'><button id='occluded' style='margin:0' onclick='bump()'>Covered target</button>"
            @"<div id='occluder' style='position:absolute;inset:0;background:#ddd' onclick=\"document.getElementById('decoy-count').textContent=String(++window.decoys)\">Overlay</div></div><output id='decoy-count'>0</output>"
            @"<button id='replace-increment' onclick=\"const e=document.getElementById('increment');e.replaceWith(e.cloneNode(true));\">Replace increment</button>"
            @"<script>window.clicks=0;window.decoys=0;window.bump=()=>{document.getElementById('count').textContent=String(++window.clicks)};"
            @"window.__enclave={seq:1,ids:new WeakMap([[document,1]]),nodes:new Map([[1,document]]),down:null,document,frame:'__OWNED_FRAME_ID__'};</script>";
        html=[html stringByReplacingOccurrencesOfString:@"__OWNED_FRAME_ID__" withString:NSUUID.UUID.UUIDString];
        [owner.view loadHTMLString:html baseURL:[NSURL URLWithString:OwnedDocumentURL]];
        if (!pump_until(^BOOL{return owner.loaded||owner.failed;},5) || owner.failed) { *status=-3;return NULL; }
        *status=0;
        return (__bridge_retained void *)owner;
    } @catch(NSException *exception) { *status=-4;return NULL; } }
}

int enclave_webkit_eval(void *handle,const char *source,unsigned char *output,size_t cap) {
    if (!handle||!source||!output||cap<2||!NSThread.isMainThread) return -1;
    @autoreleasepool { @try {
        EnclaveOwnedWebKit *owner=(__bridge EnclaveOwnedWebKit *)handle;
        if (owner.failed) return -2;
        NSString *script=[NSString stringWithUTF8String:source];
        if (!script) return -3;
        __block BOOL done=NO;
        __block NSData *data=nil;
        [owner.view evaluateJavaScript:script completionHandler:^(id result,NSError *error){
            if (!error && [NSJSONSerialization isValidJSONObject:result]) data=[NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
            done=YES;
        }];
        if (!pump_until(^BOOL{return done;},3)) { owner.failed=YES;[owner.view stopLoading];return -4; }
        if (!data||data.length>=cap) return -5;
        medepoty(output,data.bytes,data.length);
        return (int)data.length;
    } @catch(NSException *exception) { return -6; } }
}

void enclave_webkit_destroy(void *handle) {
    if (handle) { @autoreleasepool {
        EnclaveOwnedWebKit *owner=(__bridge_transfer EnclaveOwnedWebKit *)handle;
        [owner.view stopLoading];owner.view.navigationDelegate=nil;owner.view.UIDelegate=nil;
    } }
}

// Exercise the actual ownership helper without starting WebKit or accepting
// caller paths. This hook owns its mkdtemp fixture and exists only in debug.
#ifdef depot_OWNED_BROWSER_TESTING
static BOOL sameOwnedTestIdentity(NSURL *path, const struct stat *before) {
    struct stat after;
    return lstat(path.fileSystemRepresentation,&after)==0
        && before->st_dev==after.st_dev && before->st_ino==after.st_ino
        && before->st_mode==after.st_mode && before->st_uid==after.st_uid;
}

int enclave_webkit_directory_ownership_check(void) {
    @autoreleasepool {
        NSString *pattern=[NSTemporaryDirectory() stringByAppendingPathComponent:@"depot-webkit-owner-XXXXXX"];
        char *temporary=strdup(pattern.fileSystemRepresentation);
        if (!temporary) return -1;
        if (!mkdtemp(temporary)) { free(temporary);return -2; }
        NSURL *root=[NSURL fileURLWithFileSystemRepresentation:temporary isDirectory:YES relativeToURL:nil];
        free(temporary);
        NSFileManager *files=NSFileManager.defaultManager;
        NSData *content=[@"preserve-existing-browser-owner" dataUsingEncoding:NSUTF8StringEncoding];
        int result=0;
        @try {
            NSURL *collision=[root URLByAppendingPathComponent:@"existing" isDirectory:YES];
            NSURL *sentinel=[collision URLByAppendingPathComponent:@"sentinel"];
            struct stat directoryBefore,sentinelBefore;
            if (mkdir(collision.fileSystemRepresentation,0700)!=0
                || ![content writeToURL:sentinel options:NSDataWritingWithoutOverwriting error:nil]
                || lstat(collision.fileSystemRepresentation,&directoryBefore)!=0
                || lstat(sentinel.fileSystemRepresentation,&sentinelBefore)!=0) result=-3;
            if (!result) {
                @autoreleasepool {
                    EnclaveOwnedWebKit *owner=[EnclaveOwnedWebKit new];
                    if (createOwnedDirectory(owner,collision)||owner.directory) result=-4;
                }
                if (!sameOwnedTestIdentity(collision,&directoryBefore)
                    || !sameOwnedTestIdentity(sentinel,&sentinelBefore)
                    || ![[NSData dataWithContentsOfURL:sentinel] isEqualToData:content]) result=-5;
            }
            NSURL *existingFile=[root URLByAppendingPathComponent:@"existing-file"];
            struct stat fileBefore;
            if (!result) {
                if (![content writeToURL:existingFile options:NSDataWritingWithoutOverwriting error:nil]
                    || lstat(existingFile.fileSystemRepresentation,&fileBefore)!=0) result=-6;
                if (!result) {
                    @autoreleasepool {
                        EnclaveOwnedWebKit *owner=[EnclaveOwnedWebKit new];
                        if (createOwnedDirectory(owner,existingFile)||owner.directory) result=-7;
                    }
                    if (!sameOwnedTestIdentity(existingFile,&fileBefore)
                        || ![[NSData dataWithContentsOfURL:existingFile] isEqualToData:content]) result=-8;
                }
            }
            NSURL *link=[root URLByAppendingPathComponent:@"existing-link" isDirectory:YES];
            struct stat linkBefore;
            if (!result) {
                if (symlink("existing",link.fileSystemRepresentation)!=0
                    || lstat(link.fileSystemRepresentation,&linkBefore)!=0
                    || !S_ISLNK(linkBefore.st_mode)) result=-9;
                if (!result) {
                    @autoreleasepool {
                        EnclaveOwnedWebKit *owner=[EnclaveOwnedWebKit new];
                        if (createOwnedDirectory(owner,link)||owner.directory) result=-10;
                    }
                    if (!sameOwnedTestIdentity(link,&linkBefore)
                        || !sameOwnedTestIdentity(collision,&directoryBefore)
                        || !sameOwnedTestIdentity(sentinel,&sentinelBefore)
                        || ![[NSData dataWithContentsOfURL:sentinel] isEqualToData:content]) result=-11;
                }
            }
            NSURL *owned=[root URLByAppendingPathComponent:@"owned" isDirectory:YES];
            if (!result) {
                @autoreleasepool {
                    EnclaveOwnedWebKit *owner=[EnclaveOwnedWebKit new];
                    struct stat created;
                    if (!createOwnedDirectory(owner,owned)
                        || ![owner.directory isEqual:owned]
                        || lstat(owned.fileSystemRepresentation,&created)!=0
                        || !S_ISDIR(created.st_mode)||created.st_uid!=geteuid()
                        || (created.st_mode&0777)!=0700) result=-12;
                }
                struct stat absent;
                if (lstat(owned.fileSystemRepresentation,&absent)==0||errno!=ENOENT) result=-13;
                if (!sameOwnedTestIdentity(collision,&directoryBefore)
                    || !sameOwnedTestIdentity(sentinel,&sentinelBefore)
                    || !sameOwnedTestIdentity(existingFile,&fileBefore)
                    || !sameOwnedTestIdentity(link,&linkBefore)
                    || ![[NSData dataWithContentsOfURL:sentinel] isEqualToData:content]
                    || ![[NSData dataWithContentsOfURL:existingFile] isEqualToData:content]) result=-14;
            }
        } @catch (NSException *exception) { (void)exception;result=-15; }
        NSError *cleanup=nil;
        if (![files removeItemAtURL:root error:&cleanup]&&!result) result=-16;
        return result;
    }
}
#endif
