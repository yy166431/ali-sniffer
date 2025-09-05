// AliSniffer.m — 静默版（带 Headers 抓取）
// 说明：只在命中“可播 URL”时弹窗 + 复制剪贴板；默认不打 NSLog、不写文件、不上报。
// 覆盖链路：NSURLSessionTask / NSURLProtocol(MIME & #EXTM3U) / CFReadStream(CFHTTPMessage 取头)
//          AVPlayerItem/AVURLAsset / WKWebView(JS) / libcurl(CURLOPT_URL/HTTPHEADER + curl_slist_append)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

#pragma mark - 配置项（可按需修改）

// 关闭/开启调试日志（默认关闭）
#ifndef ENABLE_DEBUG_LOG
#define LOG(...)
#else
#define LOG(...) NSLog(__VA_ARGS__)
#endif

// 是否显示弹窗（1=显示；0=完全静默，仅复制到剪贴板）
#ifndef SNIFFER_ENABLE_POPUP
#define SNIFFER_ENABLE_POPUP 1
#endif

// 是否显示初始化“已加载”提示
#ifndef SNIFFER_SHOW_BOOT_POPUP
#define SNIFFER_SHOW_BOOT_POPUP 1
#endif

// 去重窗口（秒）
#ifndef SNIFFER_DEDUP_SECONDS
#define SNIFFER_DEDUP_SECONDS 10.0
#endif

#pragma mark - 噪声/白名单

static NSArray<NSString *> *BlockedSubstrings(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"log.aliyuncs.com", @"/beacon", @"/collect", @"/monitor",
            @"umeng", @"bugly", @"analytics", @"sentry"
        ];
    });
    return a;
}

static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            // 你的常见域名
            @"knyb.kuniunet.com",
            @"knydb.kuniunet.com",
            @"qiaohongb.kuniunet.com",
            @"v2.weizan.cn"
        ];
    });
    return a;
}

#pragma mark - 工具 & 判定

static inline NSString *HostOfURLString(NSString *s) {
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.lowercaseString ?: @"";
}

static inline BOOL IsNoise(NSString *lower) {
    for (NSString *k in BlockedSubstrings()) { if ([lower containsString:k]) return YES; }
    return NO;
}

static inline BOOL IsPlayableURLString(NSString *u) {
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

// 10s去重
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static inline BOOL SeenRecently(NSString *k) {
    static dispatch_once_t once; dispatch_once(&once, ^{ g_seen = [NSMutableDictionary dictionary]; });
    NSDate *now = [NSDate date]; NSDate *last = g_seen[k];
    if (last && [now timeIntervalSinceDate:last] < SNIFFER_DEDUP_SECONDS) return YES;
    g_seen[k] = now; if (g_seen.count > 300) [g_seen removeAllObjects];
    return NO;
}

static inline void CopyToPasteboard(NSString *text) {
    if (text.length) [UIPasteboard generalPasteboard].string = text;
}

static inline void ShowPopupIfNeeded(NSString *title, NSString *message) {
#if SNIFFER_ENABLE_POPUP
    if (!message.length) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            CopyToPasteboard(message);
        }]];
        [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        if (vc) [vc presentViewController:a animated:YES completion:nil];
    });
#else
    // 完全静默则仅复制
    CopyToPasteboard(message);
#endif
}

#pragma mark - 格式化 Headers & 统一上报

static NSString* FormatHeadersText(NSDictionary *headers) {
    if (headers.count == 0) return @"";
    NSMutableString *s = [NSMutableString string];
    NSArray *keys = [[headers allKeys] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    for (NSString *k in keys) {
        id v = headers[k]; if (!v) continue;
        [s appendFormat:@"%@: %@\n", k, v];
    }
    return [s copy];
}

static void Report_URL_Headers(NSString *url, NSDictionary *headers, NSString *from) {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;
    if (IsNoise(lower)) return;
    if (!IsPlayableURLString(url)) return;

    // 去重：加入部分关键头避免重复
    NSString *ua = [headers[@"User-Agent"] ?: @"" description];
    NSString *ref = [headers[@"Referer"]   ?: @"" description];
    NSString *ck  = [headers[@"Cookie"]    ?: @"" description];
    NSString *key = [NSString stringWithFormat:@"%@|%@|%@|%@", url, ua, ref, ck];
    if (SeenRecently(key)) return;

    NSMutableString *msg = [NSMutableString stringWithFormat:@"%@", url];
    NSString *hdrText = FormatHeadersText(headers);
    if (hdrText.length) [msg appendFormat:@"\n\n--- Headers ---\n%@", hdrText];

    // 标题按类型更友好
    NSString *title = @"命中可疑播放 URL";
    if ([lower containsString:@"m3u8"]) title = @"抓到 M3U8（含Headers）";
    else if ([lower containsString:@".mp4"]) title = @"抓到 MP4（含Headers）";
    else if ([lower containsString:@".flv"] ||
             [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
             (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        title = @"抓到直播流 (FLV/RTMP)（含Headers）";
    }
    ShowPopupIfNeeded(title, msg);
    LOG(@"[%@] %@\n%@", from ?: @"", title, msg);
}

static void Report_URL_Only(NSString *url, NSString *from) {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;
    if (IsNoise(lower)) return;
    if (!IsPlayableURLString(url)) return;
    if (SeenRecently(url)) return;

    NSString *title = @"命中可疑播放 URL";
    if ([lower containsString:@"m3u8"]) title = @"抓到 M3U8";
    else if ([lower containsString:@".mp4"]) title = @"抓到 MP4";
    else if ([lower containsString:@".flv"] ||
             [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
             (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        title = @"抓到直播流 (FLV/RTMP)";
    }
    ShowPopupIfNeeded(title, url);
    LOG(@"[%@] %@\n%@", from ?: @"", title, url);
}

#pragma mark - Swizzle Helper

static void Swz(Class c, SEL sel, IMP newImp, IMP *origStore) {
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    if (origStore) *origStore = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

#pragma mark - 1) NSURLSessionTask.resume（拿 URL + Headers）

static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if ([self respondsToSelector:@selector(currentRequest)]) {
            NSURLRequest *req = [self performSelector:@selector(currentRequest)];
            if ([req isKindOfClass:NSURLRequest.class] && req.URL) {
                NSDictionary *hdr = req.allHTTPHeaderFields ?: @{};
                Report_URL_Headers(req.URL.absoluteString, hdr, @"NSURLSessionTask.resume");
            }
        }
    } @catch (...) {}
    if (orig_task_resume) orig_task_resume(self, _cmd);
}

#pragma mark - 2) NSURLProtocol（识别 m3u8 / flv MIME + #EXTM3U）

@interface _SniffProto : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@property(nonatomic,strong) NSMutableData *buf;
@property(nonatomic,assign) BOOL shouted;
@end

@implementation _SniffProto
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"_SniffHandled" inRequest:request]) return NO;
    NSString *sch = request.URL.scheme.lowercaseString;
    return [sch isEqualToString:@"http"] || [sch isEqualToString:@"https"];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"_SniffHandled" inRequest:r];
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
        NSDictionary *hdr = dataTask.currentRequest.allHTTPHeaderFields ?: @{};
        NSString *url = dataTask.currentRequest.URL.absoluteString ?: @"";

        if ([mime containsString:@"mpegurl"]) {
            Report_URL_Headers(url, hdr, @"NSURLProtocol(MIME-M3U8)");
            self.shouted = YES;
        } else if ([mime containsString:@"x-flv"] || [mime containsString:@"/flv"]) {
            Report_URL_Headers(url, hdr, @"NSURLProtocol(MIME-FLV)");
            self.shouted = YES;
        }
    }
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
    if (!self.shouted && self.buf.length < 16*1024) {
        [self.buf appendData:data];
        NSString *head = [[NSString alloc] initWithData:self.buf encoding:NSUTF8StringEncoding];
        if (head && [head containsString:@"#EXTM3U"]) {
            NSDictionary *hdr = dataTask.currentRequest.allHTTPHeaderFields ?: @{};
            NSString *url = dataTask.currentRequest.URL.absoluteString ?: @"";
            Report_URL_Headers(url, hdr, @"NSURLProtocol(#EXTM3U)");
            self.shouted = YES;
        }
    }
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

static NSURLSessionConfiguration* (*orig_defCfg)(id, SEL);
static NSURLSessionConfiguration* swz_defCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_defCfg(self, _cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:_SniffProto.class]) [arr insertObject:_SniffProto.class atIndex:0];
    cfg.protocolClasses = arr; return cfg;
}
static NSURLSessionConfiguration* (*orig_ephCfg)(id, SEL);
static NSURLSessionConfiguration* swz_ephCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_ephCfg(self, _cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:_SniffProto.class]) [arr insertObject:_SniffProto.class atIndex:0];
    cfg.protocolClasses = arr; return cfg;
}

#pragma mark - 3) CFReadStreamCreateForHTTPRequest（直接从 CFHTTPMessage 取 URL+Headers）

typedef CFURLRef (*PFN_CFHTTPMessageCopyRequestURL)(CFHTTPMessageRef);
typedef CFDictionaryRef (*PFN_CFHTTPMessageCopyAllHeaderFields)(CFHTTPMessageRef);
static PFN_CFHTTPMessageCopyRequestURL        p_CFHTTPMessageCopyRequestURL = NULL;
static PFN_CFHTTPMessageCopyAllHeaderFields   p_CFHTTPMessageCopyAllHeaderFields = NULL;

typedef CFReadStreamRef (*PFN_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static PFN_CFReadStreamCreateForHTTPRequest orig_CFReadStreamCreateForHTTPRequest = NULL;

static CFReadStreamRef hook_CFReadStreamCreateForHTTPRequest(CFAllocatorRef a, CFHTTPMessageRef req) {
    NSString *urlStr = nil; NSDictionary *hdr = @{};
    if (req) {
        if (p_CFHTTPMessageCopyRequestURL) {
            CFURLRef u = p_CFHTTPMessageCopyRequestURL(req);
            if (u) urlStr = [(__bridge NSURL *)u absoluteString];
        }
        if (p_CFHTTPMessageCopyAllHeaderFields) {
            CFDictionaryRef d = p_CFHTTPMessageCopyAllHeaderFields(req);
            if (d) hdr = [(__bridge NSDictionary *)d copy] ?: @{};
        }
    }
    if (urlStr.length) {
        if (!IsNoise(urlStr.lowercaseString) && IsPlayableURLString(urlStr)) {
            Report_URL_Headers(urlStr, hdr, @"CFReadStream(HTTPRequest)");
        }
    }
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(a, req) : NULL;
}

#pragma mark - 4) AVPlayer / AVURLAsset（只有 URL 的情况也报）

static id (*orig_AVPI_initWithURL)(id, SEL, NSURL *);
static id swz_AVPI_initWithURL(id self, SEL _cmd, NSURL *url) { if (url) Report_URL_Only(url.absoluteString, @"AVPlayerItem.init"); return orig_AVPI_initWithURL(self, _cmd, url); }
static id (*orig_AVPI_playerItemWithURL)(id, SEL, NSURL *);
static id swz_AVPI_playerItemWithURL(id self, SEL _cmd, NSURL *url) { if (url) Report_URL_Only(url.absoluteString, @"AVPlayerItem.itemWithURL"); return orig_AVPI_playerItemWithURL(self, _cmd, url); }
static id (*orig_AVURLA_initWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_initWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) { if (url) Report_URL_Only(url.absoluteString, @"AVURLAsset.init"); return orig_AVURLA_initWithURL(self, _cmd, url, opt); }
static id (*orig_AVURLA_assetWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_assetWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) { if (url) Report_URL_Only(url.absoluteString, @"AVURLAsset.assetWithURL"); return orig_AVURLA_assetWithURL(self, _cmd, url, opt); }

#pragma mark - 5) WKWebView 注入（抓 H5 中的 fetch/XHR/video.src）

@interface _WKHandler : NSObject<WKScriptMessageHandler> @end
@implementation _WKHandler
- (void)userContentController:(WKUserContentController *)uc didReceiveScriptMessage:(WKScriptMessage *)m {
    if ([m.name isEqualToString:@"_S"]) {
        NSString *u = [m.body isKindOfClass:NSString.class] ? (NSString *)m.body : @"";
        if (u.length) Report_URL_Only(u, @"WKWebView(JS)");
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
    return orig_WK_init(self, _cmd, frame, cfg);
}

#pragma mark - 6) libcurl（收集 URL + HTTPHEADER + curl_slist_append）

typedef int CURLcode;
struct curl_slist { char *data; struct curl_slist *next; };

static CURLcode (*orig_curl_easy_setopt)(void *curl, int option, ...);
static struct curl_slist* (*orig_curl_slist_append)(struct curl_slist *, const char *);
static NSMutableDictionary<NSValue*, NSMutableArray<NSString*>*> *gCurlHeaders; // key: slist* 指针
static NSMutableDictionary<NSValue*, NSValue*> *gCurlHandleToSlist;             // key: curl* → slist*

static struct curl_slist* hook_curl_slist_append(struct curl_slist *lst, const char *cstr) {
    struct curl_slist *ret = orig_curl_slist_append ? orig_curl_slist_append(lst, cstr) : NULL;
    if (cstr && ret) {
        NSString *line = [NSString stringWithUTF8String:cstr];
        NSValue *key = [NSValue valueWithPointer:ret]; // 返回的新表头/节点地址
        NSMutableArray *arr = gCurlHeaders[key];
        if (!arr) { arr = [NSMutableArray array]; gCurlHeaders[key] = arr; }
        if (line.length) [arr addObject:line];
    }
    return ret;
}

static NSDictionary* CurlHeadersForHandle(void *curl, NSValue **outKey) {
    // 找到该 curl 句柄最近一次设置的 slist*
    NSValue *curlKey = [NSValue valueWithPointer:curl];
    NSValue *slistKey = gCurlHandleToSlist[curlKey];
    if (outKey) *outKey = slistKey;
    if (!slistKey) return @{};
    NSArray *lines = [gCurlHeaders[slistKey] copy] ?: @[];
    NSMutableDictionary *hdr = [NSMutableDictionary dictionary];
    for (NSString *ln in lines) {
        NSRange r = [ln rangeOfString:@":"];
        if (r.location != NSNotFound) {
            NSString *k = [ln substringToIndex:r.location];
            NSString *v = [[ln substringFromIndex:r.location+1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (k.length) hdr[k] = v ?: @"";
        }
    }
    return hdr;
}

static CURLcode hook_curl_easy_setopt(void *curl, int option, ...) {
    va_list ap; va_start(ap, option);

    switch (option) {
        case 10002: { // CURLOPT_URL (char*)
            const char *c_url = va_arg(ap, const char *);
            NSString *url = c_url ? [NSString stringWithUTF8String:c_url] : nil;
            // 取已收集到的 header（若有）
            NSDictionary *hdr = CurlHeadersForHandle(curl, NULL);
            if (url.length) {
                if (!IsNoise(url.lowercaseString) && IsPlayableURLString(url)) {
                    Report_URL_Headers(url, hdr, @"libcurl(CURLOPT_URL)");
                }
            }
            // 重新吃掉参数
            va_end(ap); va_start(ap, option); (void)va_arg(ap, const char *);
            break;
        }
        case 10023: { // CURLOPT_HTTPHEADER (struct curl_slist *)
            struct curl_slist *slist = va_arg(ap, struct curl_slist *);
            if (slist) {
                NSValue *curlKey = [NSValue valueWithPointer:curl];
                NSValue *slistKey = [NSValue valueWithPointer:slist];
                gCurlHandleToSlist[curlKey] = slistKey;
                if (!gCurlHeaders[slistKey]) gCurlHeaders[slistKey] = [NSMutableArray array];
            }
            va_end(ap); va_start(ap, option); (void)va_arg(ap, const void *);
            break;
        }
        default: {
            // 对其他选项不特殊处理，继续走原函数；注意正确取参以免破坏栈
            break;
        }
    }

    CURLcode ret = 0;
    if (orig_curl_easy_setopt) {
        const void *p = va_arg(ap, const void *);
        ret = orig_curl_easy_setopt(curl, option, p);
    }
    va_end(ap);
    return ret;
}

static void InstallCurlHooks(void) {
    gCurlHeaders = [NSMutableDictionary dictionary];
    gCurlHandleToSlist = [NSMutableDictionary dictionary];
    struct rebinding rbs[] = {
        {"curl_easy_setopt", (void *)hook_curl_easy_setopt, (void **)&orig_curl_easy_setopt},
        {"curl_slist_append", (void *)hook_curl_slist_append, (void **)&orig_curl_slist_append}
    };
    rebind_symbols(rbs, sizeof(rbs)/sizeof(rbs[0]));
}

#pragma mark - 安装所有 Hook

__attribute__((constructor))
static void _sniffer_boot(void) {
    @autoreleasepool {
        // NSURLSessionTask.resume
        Class Task = NSClassFromString(@"NSURLSessionTask");
        if (Task && class_getInstanceMethod(Task, @selector(resume))) {
            Swz(Task, @selector(resume), (IMP)swz_task_resume, (IMP *)&orig_task_resume);
        }

        // NSURLSessionConfiguration（default / ephemeral）
        Class Cfg = NSURLSessionConfiguration.class;
        if (Cfg) {
            Method m1 = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
            if (m1) { orig_defCfg = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)swz_defCfg); }
            Method m2 = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
            if (m2) { orig_ephCfg = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)swz_ephCfg); }
        }

        // CFReadStreamCreateForHTTPRequest + 解析 CFHTTPMessage 符号
        void *hCF = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_NOW);
        if (hCF) {
            p_CFHTTPMessageCopyRequestURL =
            (PFN_CFHTTPMessageCopyRequestURL)dlsym(hCF, "CFHTTPMessageCopyRequestURL");
            p_CFHTTPMessageCopyAllHeaderFields =
            (PFN_CFHTTPMessageCopyAllHeaderFields)dlsym(hCF, "CFHTTPMessageCopyAllHeaderFields");
        }
        struct rebinding r1[] = {
            {"CFReadStreamCreateForHTTPRequest", (void*)hook_CFReadStreamCreateForHTTPRequest, (void**)&orig_CFReadStreamCreateForHTTPRequest}
        };
        rebind_symbols(r1, 1);

        // AVPlayer / AVURLAsset
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

        // WKWebView
        Class WK = NSClassFromString(@"WKWebView");
        if (WK) {
            Method m = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
            if (m) { orig_WK_init = (void *)method_getImplementation(m); method_setImplementation(m, (IMP)swz_WK_init); }
        }

        // libcurl（如果目标 App 没用，也不会崩）
        InstallCurlHooks();

#if SNIFFER_SHOW_BOOT_POPUP
        ShowPopupIfNeeded(@"插件已加载", @"开始捕获播放 URL + Headers");
#endif
    }
}
