// AliSniffer.m — 最终成品（基于你的原始源码，保留全部抓取功能 + 定时推送 + 立即推送）
// 说明：
// 1) 保留你原有的抓取点：NSURLSessionTask / NSURLProtocol(MIME|#EXTM3U) / AVPlayer* / CFReadStream / WK 注入 / (可选)libcurl
// 2) iOS16+ 默认仍关闭：NSURLProtocol / CFReadStream / libcurl（与你原设一致，避免崩）
// 3) 新增：缓存最近一次命中的播放 URL，并在命中时立即推送 + 每小时自动推送到你的 Flask 接口覆盖写入 stream_url.txt
//    - POST /api/push_raw：正文 text/plain；Header: X-Token；失败兜底 POST /api/push_form（x-www-form-urlencoded）
//    - 令牌：xZ7vN3qJc4G8f2K0bYw1sQp9LrT6D5aR ； 服务器： http://139.155.57.242:8088
// 4) 其余逻辑/过滤/弹窗完全不变，避免“抓不到/闪退”等副作用。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

// ====== 推送配置（新增）======
static NSString * const kPushRawEndpoint  = @"http://139.155.57.242:8088/api/push_raw";
static NSString * const kPushFormEndpoint = @"http://139.155.57.242:8088/api/push_form";
static NSString * const kPushToken        = @"@Yy166431";
static const NSTimeInterval kPushInterval = 3600.0; // 每小时自动推送
static NSString *g_lastPlayableURL = nil;           // 最近一次命中的播放 URL

// ====== 静默宏（默认不输出控制台）======
#ifndef ENABLE_DEBUG_LOG
#define LOG(...)
#else
#define LOG(...) NSLog(__VA_ARGS__)
#endif

// ====== 弹窗开关（1=命中时弹窗+复制，0=完全静默仅复制）======
#ifndef SNIFFER_ENABLE_POPUP
#define SNIFFER_ENABLE_POPUP 1
#endif

// ====== iOS16 安全策略（为避免崩溃，默认关闭这些模块；如你验证安全可改为 1）======
#ifndef SNIFFER_IOS16_ENABLE_NSURLPROTOCOL
#define SNIFFER_IOS16_ENABLE_NSURLPROTOCOL 0
#endif
#ifndef SNIFFER_IOS16_ENABLE_CFREADSTREAM
#define SNIFFER_IOS16_ENABLE_CFREADSTREAM 0
#endif
#ifndef SNIFFER_IOS16_ENABLE_LIBCURL
#define SNIFFER_IOS16_ENABLE_LIBCURL 0
#endif

// ====== 噪声/白名单（原样保留） ======
static NSArray<NSString *> *BlockedSubstrings(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"log.aliyuncs.com/logstores", @"/beacon", @"/monitor", @"/ums", @"/umeng",
            @"/collect", @"bugly", @"crash", @"analytics", @"sentry"
        ];
    });
    return a;
}
static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"knyb.kuniunet.com",
            @"knydb.kuniunet.com",
            @"qiaohongb.kuniunet.com",
            @"v2.weizan.cn"
        ];
    });
    return a;
}

// ====== 工具（原样保留） ======
static inline NSString *HostOfURLString(NSString *s) {
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.lowercaseString ?: @"";
}
static inline BOOL IsNoise(NSString *lower) {
    for (NSString *k in BlockedSubstrings()) if ([lower containsString:k]) return YES;
    return NO;
}
static inline BOOL IsPlayable(NSString *u) {
    if (u.length == 0) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@"m3u8"] ||
        [s containsString:@".mp4"] ||
        [s containsString:@".flv"] ||
        [s hasPrefix:@"rtmp://"] || [s hasPrefix:@"rtmps://"] ||
        (([s hasPrefix:@"ws://"] || [s hasPrefix:@"wss://"]) && [s containsString:@".flv"])) {
        return YES;
    }
    NSString *h = HostOfURLString(s);
    for (NSString *w in WhitelistedHosts()) if ([h hasSuffix:w]) return YES;
    return NO;
}
// 10s 去重
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static inline BOOL SeenRecently(NSString *k, NSTimeInterval sec) {
    static dispatch_once_t once; dispatch_once(&once, ^{ g_seen = [NSMutableDictionary dictionary]; });
    NSDate *now = [NSDate date]; NSDate *last = g_seen[k];
    if (last && [now timeIntervalSinceDate:last] < sec) return YES;
    g_seen[k] = now; if (g_seen.count > 256) [g_seen removeAllObjects]; return NO;
}
static inline void ShowPopupIfNeeded(NSString *title, NSString *msg) {
#if SNIFFER_ENABLE_POPUP
    if (!msg.length) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = msg;
        }]];
        [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        if (vc) [vc presentViewController:a animated:YES completion:nil];
    });
#else
    (void)title;
    if (msg.length) [UIPasteboard generalPasteboard].string = msg;
#endif
}

// ====== 新增：推送实现 ======
static void PushLatestURL_FormFallback(NSString *u) {
    if (!u.length) return;
    NSURL *URL = [NSURL URLWithString:kPushFormEndpoint];
    if (!URL) return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:URL];
    req.HTTPMethod = @"POST";
    [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
    [req setValue:@"application/x-www-form-urlencoded; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    NSString *body = [NSString stringWithFormat:@"content=%@",
                      [u stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLQueryAllowedCharacterSet]];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, __unused NSURLResponse *r, __unused NSError *e) {
        LOG(@"[AliSniffer] push_form done");
    }] resume];
}

static void PushLatestURL(void) {
    @try {
        NSString *u = g_lastPlayableURL;
        if (!u.length) return;
        NSURL *URL = [NSURL URLWithString:kPushRawEndpoint];
        if (!URL) return;
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:URL];
        req.HTTPMethod = @"POST";
        [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
        [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = [u dataUsingEncoding:NSUTF8StringEncoding];
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSHTTPURLResponse *resp = (NSHTTPURLResponse *)r;
            if (e || resp.statusCode < 200 || resp.statusCode >= 300) {
                // 兜底走 form
                PushLatestURL_FormFallback(u);
            }
            LOG(@"[AliSniffer] push_raw -> %ld, err=%@", (long)resp.statusCode, e);
        }] resume];
    } @catch (...) {}
}

// ====== 修改：ReportURL（仅新增缓存与立即推送，其他保持不变） ======
static inline void ReportURL(NSString *url) {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;
    if (IsNoise(lower)) return;
    if (!IsPlayable(lower)) return;
    if (SeenRecently(url, 10.0)) return;

    // 缓存最近一次命中
    g_lastPlayableURL = url;

    if ([lower containsString:@"m3u8"]) {
        ShowPopupIfNeeded(@"抓到 M3U8", url);
    } else if ([lower containsString:@".mp4"]) {
        ShowPopupIfNeeded(@"抓到 MP4", url);
    } else if ([lower containsString:@".flv"] ||
               [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
               (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        ShowPopupIfNeeded(@"抓到直播流 (FLV/RTMP)", url);
    } else {
        ShowPopupIfNeeded(@"命中可疑播放 URL", url);
    }

    // 新增：命中后立即推送一次（避免等 1 小时）
    PushLatestURL();
}

static inline NSString *ToURLString(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:NSString.class]) return obj;
    if ([obj isKindOfClass:NSURL.class])    return [(NSURL *)obj absoluteString];
    @try {
        id v = [obj respondsToSelector:@selector(URL)] ? [obj performSelector:@selector(URL)] : nil;
        if (!v && [obj respondsToSelector:@selector(url)]) v = [obj performSelector:@selector(url)];
        if ([v isKindOfClass:NSString.class]) return v;
        if ([v isKindOfClass:NSURL.class])    return [(NSURL *)v absoluteString];
    } @catch (...) {}
    return nil;
}
static inline void Swz(Class c, SEL sel, IMP newImp, IMP *origStore) {
    if (!c || !sel || !newImp) return;
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    if (origStore) *origStore = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

// ====== 1) NSURLSessionTask.resume （原样保留）======
static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if ([self respondsToSelector:@selector(currentRequest)]) {
            NSURLRequest *req = [self performSelector:@selector(currentRequest)];
            if ([req isKindOfClass:NSURLRequest.class] && req.URL) ReportURL(req.URL.absoluteString);
        }
    } @catch (...) {}
    if (orig_task_resume) orig_task_resume(self, _cmd);
}

// ====== 2) NSURLProtocol（仅 iOS14/15 启用；iOS16 默认关闭）======
@interface _SniffProto : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@property(nonatomic,strong) NSMutableData *buf;
@property(nonatomic,assign) BOOL shouted;
@end

@implementation _SniffProto
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"_SniffDone" inRequest:request]) return NO;
    NSString *sch = request.URL.scheme.lowercaseString;
    return [sch isEqualToString:@"http"] || [sch isEqualToString:@"https"];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"_SniffDone" inRequest:r];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.defaultSessionConfiguration
                                                    delegate:self
                                               delegateQueue:nil];
    self.task = [s dataTaskWithRequest:r];
    self.buf = [NSMutableData data];
    [self.task resume];
}
- (void)stopLoading { [self.task cancel]; self.task = nil; self.buf = nil; }

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
 didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];

    if (!self.shouted) {
        NSString *mime = response.MIMEType.lowercaseString ?: @"";
        if ([mime containsString:@"mpegurl"]) { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; }
        else if ([mime containsString:@"x-flv"] || [mime containsString:@"/flv"]) { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; }
    }
    completionHandler(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
    if (!self.shouted && self.buf.length < 16*1024) {
        [self.buf appendData:data];
        NSString *head = [[NSString alloc] initWithData:self.buf encoding:NSUTF8StringEncoding];
        if (head && [head containsString:@"#EXTM3U"]) { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; }
    }
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

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

// ====== 3) CFReadStream（仅 iOS14/15 启用；iOS16 默认关闭）======
typedef CFURLRef (*PFN_CFHTTPMessageCopyRequestURL)(CFHTTPMessageRef);
static PFN_CFHTTPMessageCopyRequestURL p_CFHTTPMessageCopyRequestURL = NULL;
typedef CFReadStreamRef (*PFN_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static PFN_CFReadStreamCreateForHTTPRequest orig_CFReadStreamCreateForHTTPRequest = NULL;

static CFReadStreamRef hook_CFReadStreamCreateForHTTPRequest(CFAllocatorRef a, CFHTTPMessageRef req) {
    if (req && p_CFHTTPMessageCopyRequestURL) {
        CFURLRef u = p_CFHTTPMessageCopyRequestURL(req);
        if (u) { NSString *s = [(__bridge NSURL *)u absoluteString]; if (s.length) ReportURL(s); }
    }
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(a, req) : NULL;
}

// ====== 4) AVPlayer / AVURLAsset（iOS14+ 通用）======
static id (*orig_AVPI_initWithURL)(id, SEL, NSURL *);
static id swz_AVPI_initWithURL(id self, SEL _cmd, NSURL *url) { if (url) ReportURL(url.absoluteString); return orig_AVPI_initWithURL(self, _cmd, url); }
static id (*orig_AVPI_playerItemWithURL)(id, SEL, NSURL *);
static id swz_AVPI_playerItemWithURL(id self, SEL _cmd, NSURL *url) { if (url) ReportURL(url.absoluteString); return orig_AVPI_playerItemWithURL(self, _cmd, url); }
static id (*orig_AVURLA_initWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_initWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) { if (url) ReportURL(url.absoluteString); return orig_AVURLA_initWithURL(self, _cmd, url, opt); }
static id (*orig_AVURLA_assetWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_assetWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) { if (url) ReportURL(url.absoluteString); return orig_AVURLA_assetWithURL(self, _cmd, url, opt); }

// ====== 5) WKWebView 注入（iOS14+ 通用，尽量安全）======
@interface _WKHandler : NSObject<WKScriptMessageHandler> @end
@implementation _WKHandler
- (void)userContentController:(WKUserContentController *)uc didReceiveScriptMessage:(WKScriptMessage *)m {
    if ([m.name isEqualToString:@"_S"]) {
        NSString *u = [m.body isKindOfClass:NSString.class] ? (NSString *)m.body : @"";
        if (u.length) ReportURL(u);
    }
}
@end
static id (*orig_WK_init)(id, SEL, CGRect, WKWebViewConfiguration *);
static id swz_WK_init(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    if (cfg) {
        _WKHandler *h = [_WKHandler new];
        [cfg.userContentController addScriptMessageHandler:h name:@"_S"];
        NSString *js =
        @"(function(){function r(u){try{if(u&&/(m3u8|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)/i.test(u)){window.webkit.messageHandlers._S.postMessage(u);}}catch(e){}}"
         "var f=window.fetch;if(f){window.fetch=function(){var u=arguments[0];if(typeof u==='string'){r(u);}return f.apply(this,arguments).then(function(res){try{var u=res&&res.url;if(u)r(u);}catch(e){}return res;});};}"
         "var X=window.XMLHttpRequest;if(X){var o=X.prototype.open,s=X.prototype.send;X.prototype.open=function(m,u){try{this.__u=u;r(u);}catch(e){}return o.apply(this,arguments)};X.prototype.send=function(){try{r(this.__u);}catch(e){}return s.apply(this,arguments)};}"
         "if(window.HTMLMediaElement){var d=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');if(d&&d.set){Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{r(v);}catch(e){}return d.set.call(this,v);},get:d.get});}}"
        "})();";
        WKUserScript *sc = [[WKUserScript alloc] initWithSource:js injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
        [cfg.userContentController addUserScript:sc];
        objc_setAssociatedObject(cfg, "_wk_h", h, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(cfg, "_wk_s", sc, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return orig_WK_init ? orig_WK_init(self, _cmd, frame, cfg) : self;
}

// ====== 6) libcurl（仅 iOS14/15 启用；iOS16 默认关闭）======
typedef int CURLcode;
static CURLcode (*orig_curl_easy_setopt)(void *curl, int option, ...);
static CURLcode hook_curl_easy_setopt(void *curl, int option, ...) {
    va_list ap; va_start(ap, option);
    if (option == 10002 /* CURLOPT_URL */) {
        const char *c = va_arg(ap, const char *); if (c) { NSString *u = [NSString stringWithUTF8String:c]; if (u.length) ReportURL(u); }
        va_end(ap); va_start(ap, option); (void)va_arg(ap, const char *);
    }
    CURLcode ret = 0;
    if (orig_curl_easy_setopt) { const void *p = va_arg(ap, const void *); ret = orig_curl_easy_setopt(curl, option, p); }
    va_end(ap); return ret;
}
static inline void HookCurlIfPresent(void) {
    rebind_symbols((struct rebinding[]){{"curl_easy_setopt",(void*)hook_curl_easy_setopt,(void**)&orig_curl_easy_setopt}},1);
}

// ====== 安装 Hook（原样保留 + 新增定时推送）======
__attribute__((constructor))
static void _sniffer_init(void) {
    @autoreleasepool {
        // 轻微延迟，避免和 App 启动并发冲突
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            // 统一：NSURLSessionTask.resume
            Class Task = NSClassFromString(@"NSURLSessionTask");
            if (Task && class_getInstanceMethod(Task, @selector(resume))) Swz(Task, @selector(resume), (IMP)swz_task_resume, (IMP *)&orig_task_resume);

            // WKWebView（安全）
            Class WK = NSClassFromString(@"WKWebView");
            if (WK) {
                Method m = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
                if (m) { orig_WK_init = (void *)method_getImplementation(m); method_setImplementation(m, (IMP)swz_WK_init); }
            }

            // AVPlayer / AVURLAsset（安全）
            Class PI = NSClassFromString(@"AVPlayerItem");
            if (PI) {
                Method m1 = class_getInstanceMethod(PI, @selector(initWithURL:));
                if (m1) { orig_AVPI_initWithURL = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)swz_AVPI_initWithURL); }
                Method m2 = class_getClassMethod(PI, @selector(playerItemWithURL:));
                if (m2) { orig_AVPI_playerItemWithURL = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)swz_AVPI_playerItemWithURL); }
            }
            Class UA = NSClassFromString(@"AVURLAsset");
            if (UA) {
                Method m3 = class_getInstanceMethod(UA, @selector(initWithURL:options:));
                if (m3) { orig_AVURLA_initWithURL = (void *)method_getImplementation(m3); method_setImplementation(m3, (IMP)swz_AVURLA_initWithURL); }
                Method m4 = class_getClassMethod(UA, @selector(URLAssetWithURL:options:));
                if (m4) { orig_AVURLA_assetWithURL = (void *)method_getImplementation(m4); method_setImplementation(m4, (IMP)swz_AVURLA_assetWithURL); }
            }

            // 按系统版本选择性启用高侵入模块
            if (@available(iOS 16.0, *)) {
                // iOS16+：默认不启用 NSURLProtocol / CFReadStream / libcurl（避免崩溃）
                if (SNIFFER_IOS16_ENABLE_NSURLPROTOCOL) {
                    Class Cfg = NSURLSessionConfiguration.class;
                    if (Cfg) {
                        Method m1 = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
                        if (m1) { orig_defCfg = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)swz_defCfg); }
                        Method m2 = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
                        if (m2) { orig_ephCfg = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)swz_ephCfg); }
                    }
                }
                if (SNIFFER_IOS16_ENABLE_CFREADSTREAM) {
                    void *hCF = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_NOW);
                    if (hCF) p_CFHTTPMessageCopyRequestURL = (PFN_CFHTTPMessageCopyRequestURL)dlsym(hCF, "CFHTTPMessageCopyRequestURL");
                    rebind_symbols((struct rebinding[]){{"CFReadStreamCreateForHTTPRequest",(void*)hook_CFReadStreamCreateForHTTPRequest,(void**)&orig_CFReadStreamCreateForHTTPRequest}},1);
                }
                if (SNIFFER_IOS16_ENABLE_LIBCURL) {
                    HookCurlIfPresent();
                }
            } else {
                // iOS14/15：启用全部
                Class Cfg = NSURLSessionConfiguration.class;
                if (Cfg) {
                    Method m1 = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
                    if (m1) { orig_defCfg = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)swz_defCfg); }
                    Method m2 = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
                    if (m2) { orig_ephCfg = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)swz_ephCfg); }
                }
                void *hCF = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_NOW);
                if (hCF) p_CFHTTPMessageCopyRequestURL = (PFN_CFHTTPMessageCopyRequestURL)dlsym(hCF, "CFHTTPMessageCopyRequestURL");
                rebind_symbols((struct rebinding[]){{"CFReadStreamCreateForHTTPRequest",(void*)hook_CFReadStreamCreateForHTTPRequest,(void**)&orig_CFReadStreamCreateForHTTPRequest}},1);
                HookCurlIfPresent();
            }

            // 新增：定时自动推送（不影响任何抓取流程）
            [NSTimer scheduledTimerWithTimeInterval:kPushInterval repeats:YES block:^(__unused NSTimer * _Nonnull t) {
                PushLatestURL();
            }];

#if SNIFFER_ENABLE_POPUP
            ShowPopupIfNeeded(@"已加载", @"已启用静默抓取 + 自动推送（iOS14/15全功能；iOS16安全模式）");
#endif
        });
    }
}
