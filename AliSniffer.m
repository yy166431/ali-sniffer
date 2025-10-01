
//
//  AliSniffer_enhanced_fix.m
//  Safe enhanced version with robust hooking (safe-init) for real-device injection.
//  - Hooks __NSCFURLSessionTask/NSURLSessionTask resume
//  - Hooks NSURLSession dataTaskWithRequest:
//  - Adds larger sniff buffer, delayed detection, header capture, AVPlayer replaceCurrentItem/playImmediatelyAtRate, WK MSE interception
//
//  Drop into your project / replace previous AliSniffer and inject. Backup original first.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

// ---------- Config ----------
static NSString * const kPushRawEndpoint  = @"http://139.155.57.242:8088/api/push_raw";
static NSString * const kPushToken        = @"@Yy166431";
static const NSTimeInterval kPushInterval = 3600.0;

#ifndef SNIFFER_ENABLE_POPUP
#define SNIFFER_ENABLE_POPUP 1
#endif

// Enable for debug logs during troubleshooting
#define ENABLE_DEBUG_LOG 1
#ifdef ENABLE_DEBUG_LOG
#define LOG(...) NSLog(__VA_ARGS__)
#else
#define LOG(...)
#endif

// ---------- Globals ----------
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static NSString *g_lastPlayableURL = nil;
static dispatch_queue_t g_sniffer_queue;
static void ensure_globals() {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_seen = [NSMutableDictionary dictionary];
        g_sniffer_queue = dispatch_queue_create("com.alisniffer.queue", DISPATCH_QUEUE_SERIAL);
    });
}

// ---------- Utilities ----------
static inline BOOL SeenRecently_internal(NSString *k, NSTimeInterval sec) {
    if (!k) return NO;
    NSDate *now = [NSDate date];
    NSDate *last = g_seen[k];
    if (last && [now timeIntervalSinceDate:last] < sec) return YES;
    g_seen[k] = now;
    if (g_seen.count > 2048) [g_seen removeAllObjects];
    return NO;
}
static inline BOOL SeenRecently(NSString *k, NSTimeInterval sec) {
    __block BOOL r;
    dispatch_sync(g_sniffer_queue, ^{
        r = SeenRecently_internal(k, sec);
    });
    return r;
}

static inline BOOL IsNoise(NSString *lower) {
    if (!lower) return YES;
    NSArray *noise = @[@"log.aliyuncs.com", @"beacon", @"/monitor", @"/ums", @"/umeng", @"/collect", @"bugly", @"crash", @"analytics", @"sentry"];
    for (NSString *n in noise) if ([lower containsString:n]) return YES;
    return NO;
}
static inline NSString *HostOfURLString(NSString *s) {
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.lowercaseString ?: @"";
}
static inline BOOL IsPlayableURL(NSString *lower) {
    if (!lower) return NO;
    if ([lower containsString:@"m3u8"] || [lower containsString:@".mp4"] || [lower containsString:@".flv"]) return YES;
    if ([lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"]) return YES;
    if (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"]) return YES;
    NSArray *wh = @[@"knyb.kuniunet.com",@"knydb.kuniunet.com",@"v2.weizan.cn"];
    for (NSString *w in wh) if ([HostOfURLString(lower) hasSuffix:w]) return YES;
    return NO;
}

static inline BOOL HasAuthKey(NSString *lower) {
    if (!lower) return NO;
    return ([lower containsString:@"auth_key="] || [lower containsString:@"authkey="]);
}
static inline NSString *BaseURLWithoutQuery(NSString *s) {
    if (!s.length) return @"";
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    if (!c) return s;
    c.query = nil; c.fragment = nil;
    return c.string ?: s;
}

// ---------- UI ----------
static void ShowPopupIfNeeded(NSString *title, NSString *msg) {
#if SNIFFER_ENABLE_POPUP
    if (!msg.length) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = msg;
        }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *w = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        UIViewController *vc = w.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        if (vc) [vc presentViewController:ac animated:YES completion:nil];
    });
#else
    if (msg.length) [UIPasteboard generalPasteboard].string = msg;
#endif
}

// ---------- Push ----------
static void PushJSON_async(NSDictionary *obj) {
    if (!obj) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        NSData *d = nil;
        @try { d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil]; } @catch(...) { return; }
        if (!d) return;
        NSURL *u = [NSURL URLWithString:kPushRawEndpoint];
        if (!u) return;
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
        req.HTTPMethod = @"POST";
        [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
        [req setValue:@"application/json; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = d;
        NSURLSessionDataTask *t = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable resp, NSError * _Nullable err) {
            (void)data; (void)resp; (void)err;
        }];
        [t resume];
    });
}

// ---------- Report with headers ----------
static inline NSDictionary *DictForHeaders(NSDictionary *headers) {
    if (!headers) return @{};
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    NSArray *keys = @[@"Authorization",@"Cookie",@"Referer",@"User-Agent",@"Origin"];
    for (NSString *k in keys) {
        NSString *v = headers[k] ?: headers[k.lowercaseString];
        if (v) m[k] = v;
    }
    return m;
}
static inline void ReportURL_WithHeaders(NSString *url, NSDictionary *headers) {
    if (!url.length) return;
    NSString *lower = url.lowercaseString;
    if (IsNoise(lower)) return;
    if (!IsPlayableURL(lower)) return;

    BOOL hasAuth = HasAuthKey(lower);
    NSString *base = BaseURLWithoutQuery(lower);

    if (hasAuth) {
        if (SeenRecently(lower, 2.0)) return;
    } else {
        if (SeenRecently(base, 10.0)) return;
    }

    g_lastPlayableURL = url;

    NSString *title = nil;
    if ([lower containsString:@"m3u8"]) title = hasAuth ? @"抓到 M3U8 (auth_key优先)" : @"抓到 M3U8";
    else if ([lower containsString:@".mp4"]) title = hasAuth ? @"抓到 MP4 (auth_key优先)" : @"抓到 MP4";
    else if ([lower containsString:@".flv"] || [lower hasPrefix:@"rtmp://"]) title = hasAuth ? @"抓到 FLV/RTMP (auth_key优先)" : @"抓到 FLV/RTMP";
    else title = hasAuth ? @"命中播放 URL (auth_key优先)" : @"命中播放 URL";

    ShowPopupIfNeeded(title, url);

    NSMutableDictionary *payload = [NSMutableDictionary dictionary];
    payload[@"url"] = url;
    payload[@"time"] = @([[NSDate date] timeIntervalSince1970]);
    NSDictionary *h = DictForHeaders(headers);
    if (h.count) payload[@"headers"] = h;
    payload[@"note"] = hasAuth ? @"auth_key" : @"no_auth_key";
    PushJSON_async(payload);
}

// ---------- Hooks ----------
// NSURLSessionTask resume
static void (*orig_task_resume)(id, SEL) = NULL;
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *req = nil;
        if ([self respondsToSelector:@selector(currentRequest)]) {
            req = [self performSelector:@selector(currentRequest)];
        } else if ([self respondsToSelector:@selector(originalRequest)]) {
            req = [self performSelector:@selector(originalRequest)];
        }
        if (req && req.URL) {
            NSDictionary *hdrs = req.allHTTPHeaderFields ?: @{};
            ReportURL_WithHeaders(req.URL.absoluteString, hdrs);
            LOG(@"[AliSniffer] resume -> %@", req.URL.absoluteString);
        }
    } @catch(...) {}
    if (orig_task_resume) orig_task_resume(self, _cmd);
}

// NSURLSession dataTaskWithRequest:
static id (*orig_dataTaskWithRequest)(id, SEL, NSURLRequest *) = NULL;
static id swz_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *req) {
    @try {
        if (req && req.URL) {
            NSDictionary *hdrs = req.allHTTPHeaderFields ?: @{};
            ReportURL_WithHeaders(req.URL.absoluteString, hdrs);
            LOG(@"[AliSniffer] dataTaskWithRequest -> %@", req.URL.absoluteString);
        }
    } @catch(...) {}
    if (orig_dataTaskWithRequest) return orig_dataTaskWithRequest(self, _cmd, req);
    return nil;
}

// NSURLProtocol sniff (larger buffer, delayed detection)
@interface _SniffProto2 : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@property(nonatomic,strong) NSMutableData *buf;
@property(nonatomic,assign) BOOL shouted;
@property(nonatomic,assign) NSTimeInterval firstDataTime;
@property(nonatomic,copy) NSString *reqURL;
@property(nonatomic,strong) NSDictionary *reqHeaders;
@end

@implementation _SniffProto2
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"_SniffDone" inRequest:request]) return NO;
    NSString *sch = request.URL.scheme.lowercaseString;
    return [sch isEqualToString:@"http"] || [sch isEqualToString:@"https"];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"_SniffDone" inRequest:r];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.defaultSessionConfiguration delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:r];
    self.buf = [NSMutableData data];
    self.shouted = NO;
    self.firstDataTime = 0;
    self.reqURL = r.URL.absoluteString ?: @"";
    self.reqHeaders = r.allHTTPHeaderFields ?: @{};
    [self.task resume];
}

- (void)stopLoading { [self.task cancel]; self.task = nil; self.buf = nil; }

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
 didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    NSString *mime = response.MIMEType.lowercaseString ?: @"";
    if (!self.shouted) {
        if ([mime containsString:@"mpegurl"] || [mime containsString:@"x-flv"] || [mime containsString:@"mpeg"]) {
            ReportURL_WithHeaders(self.reqURL, self.reqHeaders);
            self.shouted = YES;
        }
    }
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];

    if (self.shouted) return;
    if (self.firstDataTime <= 0) self.firstDataTime = [[NSDate date] timeIntervalSince1970];

    NSUInteger maxBuf = 128 * 1024;
    if (self.buf.length < maxBuf) {
        NSUInteger need = MIN(maxBuf - self.buf.length, data.length);
        [self.buf appendData:[data subdataWithRange:NSMakeRange(0, need)]];
    }

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval delta = now - self.firstDataTime;
    if (delta < 0.15) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)((0.15 - delta) * NSEC_PER_SEC)), dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            [self tryAnalyzeBuffer];
        });
    } else {
        [self tryAnalyzeBuffer];
    }
}

- (void)tryAnalyzeBuffer {
    if (self.shouted) return;
    if (!self.buf || self.buf.length == 0) return;
    const uint8_t *bytes = (const uint8_t *)self.buf.bytes;
    NSUInteger n = self.buf.length;

    NSString *txt = [[NSString alloc] initWithData:self.buf encoding:NSUTF8StringEncoding];
    if (txt && ( [txt containsString:@"#EXTM3U"] || [txt containsString:@"#EXT-X-PROGRAM-DATE-TIME"] || [txt containsString:@"#EXT-X-PART"] )) {
        ReportURL_WithHeaders(self.reqURL, self.reqHeaders);
        self.shouted = YES;
        return;
    }

    if (n >= 3 && bytes[0]=='F' && bytes[1]=='L' && bytes[2]=='V') {
        ReportURL_WithHeaders(self.reqURL, self.reqHeaders);
        self.shouted = YES;
        return;
    }

    NSUInteger maxScan = MIN(n, (NSUInteger)4096);
    for (NSUInteger i=0;i+8<=maxScan;i++) {
        if (bytes[i+4]=='f' && bytes[i+5]=='t' && bytes[i+6]=='y' && bytes[i+7]=='p') {
            ReportURL_WithHeaders(self.reqURL, self.reqHeaders);
            self.shouted = YES;
            return;
        }
        if (bytes[i+4]=='m' && bytes[i+5]=='o' && bytes[i+6]=='o' && bytes[i+7]=='f') {
            ReportURL_WithHeaders(self.reqURL, self.reqHeaders);
            self.shouted = YES;
            return;
        }
    }

    if (n >= 376) {
        if (bytes[0] == 0x47 && (bytes[188] == 0x47 || (n > 2*188 && bytes[2*188] == 0x47))) {
            ReportURL_WithHeaders(self.reqURL, self.reqHeaders);
            self.shouted = YES;
            return;
        }
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

// Swizzle NSURLSessionConfiguration class methods to insert protocol
static NSURLSessionConfiguration* (*orig_defCfg)(id, SEL) = NULL;
static NSURLSessionConfiguration* swz_defCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_defCfg ? orig_defCfg(self, _cmd) : [NSURLSessionConfiguration defaultSessionConfiguration];
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:_SniffProto2.class]) [arr insertObject:_SniffProto2.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}
static NSURLSessionConfiguration* (*orig_ephCfg)(id, SEL) = NULL;
static NSURLSessionConfiguration* swz_ephCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_ephCfg ? orig_ephCfg(self, _cmd) : [NSURLSessionConfiguration ephemeralSessionConfiguration];
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:_SniffProto2.class]) [arr insertObject:_SniffProto2.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}

// AVPlayer additional hooks
static void *orig_replaceCurrentItem = NULL;
static void swz_replaceCurrentItem(id self, SEL _cmd, id item) {
    @try {
        if (item) {
            NSURL *u = nil;
            if ([item respondsToSelector:@selector(URL)]) u = [item performSelector:@selector(URL)];
            if (!u && [item respondsToSelector:@selector(asset)]) {
                id asset = [item performSelector:@selector(asset)];
                if (asset && [asset respondsToSelector:@selector(URL)]) u = [asset performSelector:@selector(URL)];
            }
            if (u && u.absoluteString) {
                NSDictionary *hdrs = @{};
                ReportURL_WithHeaders(u.absoluteString, hdrs);
                LOG(@"[AliSniffer] replaceCurrentItem -> %@", u.absoluteString);
            }
        }
    } @catch(...) {}
    ((void(*)(id,SEL,id))orig_replaceCurrentItem)(self, _cmd, item);
}

static void *orig_playImmediatelyAtRate = NULL;
static void swz_playImmediatelyAtRate(id self, SEL _cmd, float rate) {
    @try {
        id cur = nil;
        if ([self respondsToSelector:@selector(currentItem)]) cur = [self performSelector:@selector(currentItem)];
        if (cur) {
            NSURL *u = nil;
            if ([cur respondsToSelector:@selector(URL)]) u = [cur performSelector:@selector(URL)];
            if (!u && [cur respondsToSelector:@selector(asset)]) {
                id asset = [cur performSelector:@selector(asset)];
                if (asset && [asset respondsToSelector:@selector(URL)]) u = [asset performSelector:@selector(URL)];
            }
            if (u && u.absoluteString) {
                ReportURL_WithHeaders(u.absoluteString, @{});
                LOG(@"[AliSniffer] playImmediatelyAtRate -> %@", u.absoluteString);
            }
        }
    } @catch(...) {}
    ((void(*)(id,SEL,float))orig_playImmediatelyAtRate)(self, _cmd, rate);
}

// WK WebView injection for fetch/XHR and MSE appendBuffer preview
@interface _WKHandler2 : NSObject<WKScriptMessageHandler>
@end
@implementation _WKHandler2
- (void)userContentController:(WKUserContentController *)uc didReceiveScriptMessage:(WKScriptMessage *)m {
    if (!m.body) return;
    @try {
        NSString *s = [m.body description];
        if (s.length) {
            NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *j = nil;
            @try { j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil]; } @catch(...) { j = nil; }
            if (j && j[@"type"]) {
                if ([j[@"type"] isEqualToString:@"append_preview"]) {
                    NSString *info = j[@"info"] ?: @"";
                    NSString *note = [NSString stringWithFormat:@"MSE append preview: %@", info];
                    ReportURL_WithHeaders(note, @{});
                    LOG(@"[AliSniffer] MSE append preview: %@", info);
                } else if ([j[@"type"] isEqualToString:@"fetch_url"]) {
                    NSString *u = j[@"url"] ?: @"";
                    if (u.length) { ReportURL_WithHeaders(u, @{ }); LOG(@"[AliSniffer] WK fetch_url -> %@", u); }
                }
            } else {
                NSString *u = s;
                if (u.length) { ReportURL_WithHeaders(u, @{ }); LOG(@"[AliSniffer] WK raw -> %@", u); }
            }
        }
    } @catch(...) {}
}
@end

static id (*orig_WK_init)(id, SEL, CGRect, WKWebViewConfiguration *) = NULL;
static id swz_WK_init(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    if (cfg) {
        _WKHandler2 *h = [_WKHandler2 new];
        [cfg.userContentController addScriptMessageHandler:h name:@"_S2"];
        NSString *js =
        @"(function(){"
         "function post(o){try{window.webkit.messageHandlers._S2.postMessage(JSON.stringify(o));}catch(e){}}"
         "function probeURL(u){ try{ if(u && /(m3u8|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)/i.test(u)) post({type:'fetch_url',url:u}); }catch(e){} }"
         "var f=window.fetch;if(f){window.fetch=function(){var u=arguments[0]; if(typeof u==='string') probeURL(u); return f.apply(this,arguments).then(function(res){try{var u2=res&&res.url;if(u2) probeURL(u2);}catch(e){}return res;});};}"
         "var X=window.XMLHttpRequest;if(X){var o=X.prototype.open,s=X.prototype.send;X.prototype.open=function(m,u){try{this.__u=u;probeURL(u);}catch(e){}return o.apply(this,arguments)};X.prototype.send=function(){try{probeURL(this.__u);}catch(e){}return s.apply(this,arguments)};}"
         "try{var MS = window.MediaSource; if(MS){"
           "var oldAdd = MS.prototype.addSourceBuffer; MS.prototype.addSourceBuffer = function(mime){"
             "var sb = oldAdd.call(this,mime);"
             "var oldAppend = sb.appendBuffer;"
             "sb.appendBuffer = function(buf){"
               "try{ var len = buf && buf.byteLength ? buf.byteLength : 0; var preview = '';"
                 "if (len > 0) { try{ var small = buf.slice(0, Math.min(len, 512)); var arr = new Uint8Array(small); var prefix = arr.subarray(0, Math.min(64, arr.length)); var s=''; for(var i=0;i<prefix.length;i++){ s+=String.fromCharCode(prefix[i]); } preview = btoa(s);}catch(e){} }"
                 "post({type:'append_preview', info: mime + ' len=' + len + ' b64prefix=' + preview});"
               "}catch(e){}"
               "return oldAppend.apply(this, arguments);"
             "};"
             "return sb;"
           "};"
         "}}catch(e){}"
        "})();";
        WKUserScript *sc = [[WKUserScript alloc] initWithSource:js injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
        [cfg.userContentController addUserScript:sc];
    }
    return orig_WK_init ? orig_WK_init(self, _cmd, frame, cfg) : self;
}

// ---------- Safe init constructor: try multiple candidate classes and ensure metaclass swizzling ----------
__attribute__((constructor))
static void _alisniffer_safe_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            ensure_globals();
            LOG(@"[AliSniffer] safe init start");

            // Try hooking resume on likely classes
            NSArray *candidates = @[@"__NSCFURLSessionTask", @"__NSURLSessionLocalTask", @"NSURLSessionTask"];
            BOOL hookedResume = NO;
            for (NSString *clsName in candidates) {
                Class c = NSClassFromString(clsName);
                if (!c) continue;
                SEL sel = @selector(resume);
                Method m = class_getInstanceMethod(c, sel);
                if (!m) continue;
                IMP orig = method_getImplementation(m);
                if (orig) {
                    if (!orig_task_resume) orig_task_resume = (void *)orig;
                    method_setImplementation(m, (IMP)swz_task_resume);
                    LOG(@"[AliSniffer] hooked resume on %@", clsName);
                    hookedResume = YES;
                }
            }
            if (!hookedResume) LOG(@"[AliSniffer] WARNING: failed to hook resume on candidates");

            // Hook NSURLSession dataTaskWithRequest:
            Class NSURLSessionClass = NSClassFromString(@"NSURLSession");
            if (NSURLSessionClass) {
                SEL sel = @selector(dataTaskWithRequest:);
                Method m = class_getInstanceMethod(NSURLSessionClass, sel);
                if (m) {
                    orig_dataTaskWithRequest = (void *)method_getImplementation(m);
                    method_setImplementation(m, (IMP)swz_dataTaskWithRequest);
                    LOG(@"[AliSniffer] hooked NSURLSession dataTaskWithRequest:");
                } else {
                    LOG(@"[AliSniffer] WARNING: dataTaskWithRequest: not found");
                }
            }

            // Hook NSURLSessionConfiguration class methods (use metaclass)
            Class Cfg = NSClassFromString(@"NSURLSessionConfiguration");
            if (Cfg) {
                Method dm = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
                if (dm) { orig_defCfg = (void *)method_getImplementation(dm); method_setImplementation(dm, (IMP)swz_defCfg); LOG(@"[AliSniffer] hooked defaultSessionConfiguration"); }
                Method em = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
                if (em) { orig_ephCfg = (void *)method_getImplementation(em); method_setImplementation(em, (IMP)swz_ephCfg); LOG(@"[AliSniffer] hooked ephemeralSessionConfiguration"); }
            }

            // AVPlayer hooks
            Class AVP = NSClassFromString(@"AVPlayer");
            if (AVP) {
                SEL selRep = sel_registerName("replaceCurrentItemWithPlayerItem:");
                Method mr = class_getInstanceMethod(AVP, selRep);
                if (mr) { orig_replaceCurrentItem = (void *)method_getImplementation(mr); method_setImplementation(mr, (IMP)swz_replaceCurrentItem); LOG(@"[AliSniffer] hooked AVPlayer.replaceCurrentItemWithPlayerItem:"); }
                SEL selPlay = sel_registerName("playImmediatelyAtRate:");
                Method mp = class_getInstanceMethod(AVP, selPlay);
                if (mp) { orig_playImmediatelyAtRate = (void *)method_getImplementation(mp); method_setImplementation(mp, (IMP)swz_playImmediatelyAtRate); LOG(@"[AliSniffer] hooked AVPlayer.playImmediatelyAtRate:"); }
            } else {
                LOG(@"[AliSniffer] AVPlayer class not present");
            }

            // WKWebView hook
            Class WK = NSClassFromString(@"WKWebView");
            if (WK) {
                Method m = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
                if (m) { orig_WK_init = (void *)method_getImplementation(m); method_setImplementation(m, (IMP)swz_WK_init); LOG(@"[AliSniffer] hooked WKWebView initWithFrame:configuration:"); }
            }

#if SNIFFER_ENABLE_POPUP
            ShowPopupIfNeeded(@"AliSniffer", @"Safe enhanced hooks installed (debug ON)");
#endif

            [NSTimer scheduledTimerWithTimeInterval:kPushInterval repeats:YES block:^(__unused NSTimer * _Nonnull t) {
                if (g_lastPlayableURL.length) {
                    NSMutableDictionary *p = [NSMutableDictionary dictionary];
                    p[@"url"] = g_lastPlayableURL;
                    p[@"time"] = @([[NSDate date] timeIntervalSince1970]);
                    PushJSON_async(p);
                }
            }];

            LOG(@"[AliSniffer] safe init done");
        });
    }
}
