// AliSniffer.m —— iOS14 实机抓取播放源（m3u8/mp4/flv/rtmp + 白名单域名）
// 增强：当能获取到 NSURLRequest 时，同时弹出并复制 「URL + Headers」(UA/Referer/Origin/Cookie/其它)
// 覆盖：AliPlayer / NSURLSession / NSURLProtocol(MIME/#EXTM3U/x-flv)
//      CFReadStream(fishhook) / AVPlayer(AVPlayerItem/AVURLAsset)
//      WKWebView(JS：fetch/XHR/video.src) / libcurl(CURLOPT_URL)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <WebKit/WebKit.h>
#import "fishhook.h"

#pragma mark - 配置：黑白名单

static NSArray<NSString *> *BlockedSubstrings(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"log.aliyuncs.com/logstores",
            @"/beacon", @"/collect", @"/monitor", @"/log",
            @"umeng", @"bugly"
        ];
    });
    return a;
}

static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"knydb.kuniunet.com",
            @"v2.weizan.cn",
            // 你可在此继续追加
        ];
    });
    return a;
}

#pragma mark - 弹窗 & 过滤

static void ShowPopup(NSString *title, NSString *msg) {
    if (msg.length == 0) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIPasteboard.generalPasteboard.string = msg;
        UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            UIPasteboard.generalPasteboard.string = msg;
        }]];
        [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        [vc presentViewController:a animated:YES completion:nil];
    });
}

static NSString *HostFromString(NSString *s) {
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.lowercaseString ?: @"";
}

static BOOL IsNoiseURL(NSString *lower) {
    for (NSString *k in BlockedSubstrings()) {
        if ([lower containsString:k]) return YES;
    }
    return NO;
}

static BOOL IsPlayableURL(NSString *url) {
    if (url.length == 0) return NO;
    NSString *lower = url.lowercaseString;

    if ([lower containsString:@"m3u8"] ||
        [lower containsString:@".mp4"] ||
        [lower containsString:@".flv"] ||
        [lower hasPrefix:@"rtmp://"]  || [lower hasPrefix:@"rtmps://"] ||
        (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        return YES;
    }

    NSString *host = HostFromString(lower);
    for (NSString *h in WhitelistedHosts()) {
        if ([host hasSuffix:h]) return YES;
    }
    return NO;
}

// 10 秒去重
static NSMutableDictionary<NSString*, NSDate*> *g_recent;
static BOOL SeenRecently(NSString *key, NSTimeInterval sec) {
    static dispatch_once_t once; dispatch_once(&once, ^{ g_recent = [NSMutableDictionary dictionary]; });
    NSDate *now = [NSDate date];
    NSDate *last = g_recent[key];
    if (last && [now timeIntervalSinceDate:last] < sec) return YES;
    g_recent[key] = now;
    if (g_recent.count > 200) [g_recent removeAllObjects];
    return NO;
}

#pragma mark - 汇总并弹出 URL / URL+Headers

// 将头按常见顺序排一下，便于粘贴到 PC
static NSString *AS_BuildHeadersText(NSDictionary *hdr) {
    if (hdr.count == 0) return @"";
    NSMutableArray<NSString *> *lines = [NSMutableArray array];

    NSString *ua = hdr[@"User-Agent"]; if (ua) [lines addObject:[NSString stringWithFormat:@"User-Agent: %@", ua]];
    NSString *ref= hdr[@"Referer"];    if (ref)[lines addObject:[NSString stringWithFormat:@"Referer: %@", ref]];
    NSString *ori= hdr[@"Origin"];     if (ori)[lines addObject:[NSString stringWithFormat:@"Origin: %@", ori]];
    NSString *ck = hdr[@"Cookie"];     if (ck) [lines addObject:[NSString stringWithFormat:@"Cookie: %@", ck]];

    for (NSString *k in hdr.allKeys) {
        if ([k isEqualToString:@"User-Agent"] || [k isEqualToString:@"Referer"] ||
            [k isEqualToString:@"Origin"] || [k isEqualToString:@"Cookie"]) continue;
        id v = hdr[k]; if (!v) continue;
        [lines addObject:[NSString stringWithFormat:@"%@: %@", k, v]];
    }
    return [lines componentsJoinedByString:@"\n"];
}

// 仅 URL（兼容你原来的所有抓点）
static void ReportURL_Only(NSString *url, NSString *from) {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;
    if (IsNoiseURL(lower)) return;
    if (!IsPlayableURL(url)) return;
    if (SeenRecently(url, 10.0)) return;

    NSString *title = @"命中可疑播放 URL";
    if ([lower containsString:@"m3u8"]) title = @"抓到 M3U8";
    else if ([lower containsString:@".mp4"]) title = @"抓到 MP4";
    else if ([lower containsString:@".flv"] ||
             [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
             (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        title = @"抓到直播流 (FLV/RTMP)";
    }
    NSLog(@"[AliSniffer] %@(%@): %@", title, from, url);
    ShowPopup(title, url);
}

// URL + Headers（当能拿到 NSURLRequest 时用这个）
static void ReportURL_WithHeaders(NSString *url, NSDictionary *headers, NSString *from) {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;
    if (IsNoiseURL(lower)) return;
    if (!IsPlayableURL(url)) return;

    // 去重 key：URL + UA/Referer/Cookie（避免同 URL 不停弹）
    NSString *ua = [headers[@"User-Agent"] ?: @"" description];
    NSString *rf = [headers[@"Referer"] ?: @"" description];
    NSString *ck = [headers[@"Cookie"] ?: @"" description];
    NSString *uniq = [NSString stringWithFormat:@"%@|%@|%@|%@", url, ua, rf, ck];
    if (SeenRecently(uniq, 10.0)) return;

    NSString *hdrText = AS_BuildHeadersText(headers ?: @{});
    NSString *title = @"命中可疑播放 URL";
    if ([lower containsString:@"m3u8"]) title = @"抓到 M3U8（含Headers）";
    else if ([lower containsString:@".mp4"]) title = @"抓到 MP4（含Headers）";
    else if ([lower containsString:@".flv"] ||
             [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
             (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        title = @"抓到直播流 (FLV/RTMP)（含Headers）";
    }

    NSMutableString *msg = [NSMutableString stringWithFormat:@"URL:\n%@\n", url];
    if (hdrText.length) [msg appendFormat:@"\nHeaders:\n%@", hdrText];

    NSLog(@"[AliSniffer] %@(%@):\n%@", title, from, msg);
    ShowPopup(title, msg);
}

#pragma mark - 小工具

static void Swz(Class c, SEL sel, IMP newImp, IMP *origStore) {
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    if (origStore) *origStore = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

static NSString *ExtractURLStringFromObj(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:NSString.class]) return obj;
    if ([obj isKindOfClass:NSURL.class])    return [(NSURL *)obj absoluteString];
    @try {
        id v = nil;
        if ([obj respondsToSelector:@selector(URL)])       v = [obj performSelector:@selector(URL)];
        if (!v && [obj respondsToSelector:@selector(url)]) v = [obj performSelector:@selector(url)];
        if ([v isKindOfClass:NSString.class]) return v;
        if ([v isKindOfClass:NSURL.class])    return [(NSURL *)v absoluteString];
    } @catch (...) {}
    return nil;
}

#pragma mark - ① AliPlayer / AliyunVodPlayer  —— 仅 URL

static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    NSString *u = ExtractURLStringFromObj(source);
    if (u.length) ReportURL_Only(u, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

static int (*orig_Ali_prepareURL)(id, SEL, NSString *);
static int swz_Ali_prepareURL(id self, SEL _cmd, NSString *url) {
    if (url.length) ReportURL_Only(url, @"AliyunVodPlayer.prepareWithURL");
    return orig_Ali_prepareURL(self, _cmd, url);
}

static int (*orig_Ali_playURL)(id, SEL, NSString *);
static int swz_Ali_playURL(id self, SEL _cmd, NSString *url) {
    if (url.length) ReportURL_Only(url, @"AliyunVodPlayer.play");
    return orig_Ali_playURL(self, _cmd, url);
}

#pragma mark - ② NSURLSessionTask.resume —— URL + Headers

// 记录可变请求上通过 setValue/addValue 设置的头（有些库 later merge 到 immutable request）
static const void *kASHeadersKey = &kASHeadersKey;

static void AS_MergeHeadersFromRequest(NSMutableDictionary *dst, NSURLRequest *req) {
    if (req.allHTTPHeaderFields.count) [dst addEntriesFromDictionary:req.allHTTPHeaderFields];
    NSDictionary *ex = objc_getAssociatedObject((id)req, kASHeadersKey);
    if (ex.count) [dst addEntriesFromDictionary:ex];
}

static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *req = nil;
        if ([self respondsToSelector:@selector(currentRequest)]) {
            req = [self performSelector:@selector(currentRequest)];
        }
        if (!req && [self respondsToSelector:@selector(originalRequest)]) {
            req = [self performSelector:@selector(originalRequest)];
        }

        if ([req isKindOfClass:NSURLRequest.class] && req.URL.absoluteString.length) {
            NSMutableDictionary *hdr = [NSMutableDictionary dictionary];
            AS_MergeHeadersFromRequest(hdr, req);
            ReportURL_WithHeaders(req.URL.absoluteString, hdr, @"NSURLSessionTask.resume");
        }
    } @catch (...) {}
    orig_task_resume(self, _cmd);
}

// 兼容性：拦 NSMutableURLRequest 的 set/addValue 以便尽可能收集头部
static void (*orig_setValue)(id, SEL, NSString *, NSString *);
static void swz_setValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if (field.length) {
        @try {
            NSMutableDictionary *dict = objc_getAssociatedObject(self, kASHeadersKey);
            if (!dict) {
                dict = [NSMutableDictionary dictionary];
                objc_setAssociatedObject(self, kASHeadersKey, dict, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            }
            dict[field] = value ?: @"";
        } @catch (...) {}
    }
    orig_setValue(self, _cmd, value, field);
}

static void (*orig_addValue)(id, SEL, NSString *, NSString *);
static void swz_addValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if (field.length) {
        @try {
            NSMutableDictionary *dict = objc_getAssociatedObject(self, kASHeadersKey);
            if (!dict) {
                dict = [NSMutableDictionary dictionary];
                objc_setAssociatedObject(self, kASHeadersKey, dict, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            }
            // 多值头部简单拼接
            NSString *old = dict[field];
            dict[field] = old.length ? [old stringByAppendingFormat:@"; %@", value ?: @""] : (value ?: @"");
        } @catch (...) {}
    }
    orig_addValue(self, _cmd, value, field);
}

#pragma mark - ③ NSURLProtocol（识别 MIME / #EXTM3U / video/x-flv）—— URL + Headers

@interface M3U8SniffProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@property(nonatomic,strong) NSMutableData *buf;
@property(nonatomic,assign) BOOL shouted;
@end

@implementation M3U8SniffProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"M3U8SniffHandled" inRequest:request]) return NO;
    NSString *sch = request.URL.scheme.lowercaseString;
    return [sch isEqualToString:@"http"] || [sch isEqualToString:@"https"];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"M3U8SniffHandled" inRequest:r];
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
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
        if ([mime containsString:@"mpegurl"] || [mime containsString:@"x-mpegurl"]) {
            NSMutableDictionary *hdr = [NSMutableDictionary dictionary];
            AS_MergeHeadersFromRequest(hdr, dataTask.currentRequest);
            ReportURL_WithHeaders(dataTask.currentRequest.URL.absoluteString, hdr, @"NSURLProtocol(MIME-M3U8)");
            self.shouted = YES;
        }
        else if ([mime containsString:@"x-flv"] || [mime containsString:@"/flv"]) {
            NSMutableDictionary *hdr = [NSMutableDictionary dictionary];
            AS_MergeHeadersFromRequest(hdr, dataTask.currentRequest);
            ReportURL_WithHeaders(dataTask.currentRequest.URL.absoluteString, hdr, @"NSURLProtocol(MIME-FLV)");
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
            NSMutableDictionary *hdr = [NSMutableDictionary dictionary];
            AS_MergeHeadersFromRequest(hdr, dataTask.currentRequest);
            ReportURL_WithHeaders(dataTask.currentRequest.URL.absoluteString, hdr, @"NSURLProtocol(#EXTM3U)");
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
    if (![arr containsObject:M3U8SniffProtocol.class]) [arr insertObject:M3U8SniffProtocol.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}
static NSURLSessionConfiguration* (*orig_ephCfg)(id, SEL);
static NSURLSessionConfiguration* swz_ephCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_ephCfg(self, _cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:M3U8SniffProtocol.class]) [arr insertObject:M3U8SniffProtocol.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}

#pragma mark - ④ CFReadStream Hook（运行期绑定）—— 仅 URL（保留）

typedef CFURLRef (*PFN_CFHTTPMessageCopyRequestURL)(CFHTTPMessageRef);
static PFN_CFHTTPMessageCopyRequestURL p_CFHTTPMessageCopyRequestURL = NULL;

typedef CFReadStreamRef (*PFN_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static PFN_CFReadStreamCreateForHTTPRequest orig_CFReadStreamCreateForHTTPRequest = NULL;

static CFReadStreamRef hook_CFReadStreamCreateForHTTPRequest(CFAllocatorRef a, CFHTTPMessageRef req) {
    if (req && p_CFHTTPMessageCopyRequestURL) {
        CFURLRef u = p_CFHTTPMessageCopyRequestURL(req);
        if (u) {
            NSString *url = [(__bridge NSURL *)u absoluteString];
            if (url.length) ReportURL_Only(url, @"CFReadStreamCreateForHTTPRequest");
        }
    }
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(a, req) : NULL;
}

#pragma mark - ⑤ AVPlayer / AVURLAsset —— 仅 URL（保留）

static id (*orig_AVPI_initWithURL)(id, SEL, NSURL *);
static id swz_AVPI_initWithURL(id self, SEL _cmd, NSURL *url) {
    if (url) ReportURL_Only(url.absoluteString, @"AVPlayerItem.initWithURL");
    return orig_AVPI_initWithURL(self, _cmd, url);
}
static id (*orig_AVPI_playerItemWithURL)(id, SEL, NSURL *);
static id swz_AVPI_playerItemWithURL(id self, SEL _cmd, NSURL *url) {
    if (url) ReportURL_Only(url.absoluteString, @"AVPlayerItem.playerItemWithURL");
    return orig_AVPI_playerItemWithURL(self, _cmd, url);
}
static id (*orig_AVURLA_initWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_initWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) {
    if (url) ReportURL_Only(url.absoluteString, @"AVURLAsset.initWithURL");
    return orig_AVURLA_initWithURL(self, _cmd, url, opt);
}
static id (*orig_AVURLA_assetWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_assetWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) {
    if (url) ReportURL_Only(url.absoluteString, @"AVURLAsset.assetWithURL");
    return orig_AVURLA_assetWithURL(self, _cmd, url, opt);
}

#pragma mark - ⑥ WKWebView 注入 JS —— 仅 URL（保留）

@interface AliWKHandler : NSObject<WKScriptMessageHandler>
@end
@implementation AliWKHandler
- (void)userContentController:(WKUserContentController *)uc didReceiveScriptMessage:(WKScriptMessage *)m {
    if ([m.name isEqualToString:@"AliSniffer"]) {
        NSString *url = [m.body isKindOfClass:NSString.class] ? (NSString *)m.body : @"";
        if (url.length) ReportURL_Only(url, @"WKWebView(JS)");
    }
}
@end

static char kAliWKHandlerKey;
static char kAliWKUserScriptKey;

static id (*orig_WK_init)(id, SEL, CGRect, WKWebViewConfiguration *);
static id swz_WK_init(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    if (cfg) {
        AliWKHandler *handler = [AliWKHandler new];
        objc_setAssociatedObject(cfg, &kAliWKHandlerKey, handler, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [cfg.userContentController addScriptMessageHandler:handler name:@"AliSniffer"];

        NSString *js =
        @"(function(){"
          "function report(u){try{"
            "if(u && /(m3u8|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)/i.test(u)){"
              "window.webkit.messageHandlers.AliSniffer.postMessage(u);"
            "}"
          "}catch(e){}}"
          "var _f=window.fetch; if(_f){window.fetch=function(){var u=arguments[0]; if(typeof u==='string'){report(u);} "
          "return _f.apply(this,arguments).then(function(res){try{var u=res&&res.url; if(u)report(u);}catch(e){} return res;});};}"
          "var X=window.XMLHttpRequest; if(X){var op=X.prototype.open, sd=X.prototype.send;"
          "X.prototype.open=function(m,u){try{this.__u=u;report(u);}catch(e){} return op.apply(this,arguments)};"
          "X.prototype.send=function(){try{report(this.__u);}catch(e){} return sd.apply(this,arguments)};}"
          "if(window.HTMLMediaElement){var ds=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');"
          "if(ds&&ds.set){Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{report(v);}catch(e){} return ds.set.call(this,v);},get:ds.get});}}"
        "})();";

        WKUserScript *script = [[WKUserScript alloc] initWithSource:js
                                                     injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                                  forMainFrameOnly:NO];
        [cfg.userContentController addUserScript:script];
        objc_setAssociatedObject(cfg, &kAliWKUserScriptKey, script, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return orig_WK_init(self, _cmd, frame, cfg);
}

#pragma mark - ⑦ libcurl：CURLOPT_URL —— 仅 URL（保留）

typedef int CURLcode;
static CURLcode (*orig_curl_easy_setopt)(void *curl, int option, ...);
static CURLcode hook_curl_easy_setopt(void *curl, int option, ...) {
    va_list ap; va_start(ap, option);
    if (option == 10002 /* CURLOPT_URL */) {
        const char *c_url = va_arg(ap, const char *);
        if (c_url) {
            NSString *url = [NSString stringWithUTF8String:c_url];
            if (url.length) ReportURL_Only(url, @"curl_easy_setopt(CURLOPT_URL)");
        }
        va_end(ap); va_start(ap, option); (void)va_arg(ap, const char *);
    }
    CURLcode ret = 0;
    if (orig_curl_easy_setopt) {
        const void *p = va_arg(ap, const void *);
        ret = orig_curl_easy_setopt(curl, option, p);
    }
    va_end(ap);
    return ret;
}

static void InstallCurlHook(void) {
    struct rebinding rbs[] = {
        {"curl_easy_setopt", (void *)hook_curl_easy_setopt, (void **)&orig_curl_easy_setopt}
    };
    rebind_symbols(rbs, sizeof(rbs)/sizeof(rbs[0]));
    NSLog(@"[AliSniffer] fishhook curl_easy_setopt");
}

#pragma mark - 安装所有 Hook

__attribute__((constructor))
static void _ali_sniffer_init(void) {
    @autoreleasepool {
        // AliPlayer
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        if (AliPlayer && [AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
            Swz(AliPlayer, @selector(setUrlSource:), (IMP)swz_Ali_setUrlSource, (IMP *)&orig_Ali_setUrlSource);
        }
        Class AliVod = NSClassFromString(@"AliyunVodPlayer");
        if (AliVod && [AliVod instancesRespondToSelector:@selector(prepareWithURL:)]) {
            Swz(AliVod, @selector(prepareWithURL:), (IMP)swz_Ali_prepareURL, (IMP *)&orig_Ali_prepareURL);
        }
        if (AliVod && [AliVod instancesRespondToSelector:@selector(play:)]) {
            Swz(AliVod, @selector(play:), (IMP)swz_Ali_playURL, (IMP *)&orig_Ali_playURL);
        }

        // NSURLSessionTask.resume
        Class Task = NSClassFromString(@"NSURLSessionTask");
        if (Task && class_getInstanceMethod(Task, @selector(resume))) {
            Swz(Task, @selector(resume), (IMP)swz_task_resume, (IMP *)&orig_task_resume);
        }

        // NSMutableURLRequest set/addValue（用于尽量收集头）
        Class MReq = NSClassFromString(@"NSMutableURLRequest");
        if (MReq) {
            Swz(MReq, @selector(setValue:forHTTPHeaderField:), (IMP)swz_setValue, (IMP *)&orig_setValue);
            Swz(MReq, @selector(addValue:forHTTPHeaderField:), (IMP)swz_addValue, (IMP *)&orig_addValue);
        }

        // NSURLProtocol 注入
        Class Cfg = NSURLSessionConfiguration.class;
        if ([Cfg respondsToSelector:@selector(defaultSessionConfiguration)]) {
            Method m = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
            orig_defCfg = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_defCfg);
        }
        if ([Cfg respondsToSelector:@selector(ephemeralSessionConfiguration)]) {
            Method m = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
            orig_ephCfg = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_ephCfg);
        }

        // CFReadStream hook
        void *hCF = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_NOW);
        if (hCF) {
            p_CFHTTPMessageCopyRequestURL =
            (PFN_CFHTTPMessageCopyRequestURL)dlsym(hCF, "CFHTTPMessageCopyRequestURL");
        }
        struct rebinding r1[] = {
            {"CFReadStreamCreateForHTTPRequest", (void *)hook_CFReadStreamCreateForHTTPRequest, (void **)&orig_CFReadStreamCreateForHTTPRequest}
        };
        rebind_symbols(r1, sizeof(r1)/sizeof(r1[0]));

        // AVPlayer / AVURLAsset
        Class AVPI = NSClassFromString(@"AVPlayerItem");
        if (AVPI) {
            Method m1 = class_getInstanceMethod(AVPI, @selector(initWithURL:));
            if (m1) { orig_AVPI_initWithURL = (void *)method_getImplementation(m1);
                      method_setImplementation(m1, (IMP)swz_AVPI_initWithURL); }
            Method m2 = class_getClassMethod(AVPI, @selector(playerItemWithURL:));
            if (m2) { orig_AVPI_playerItemWithURL = (void *)method_getImplementation(m2);
                      method_setImplementation(m2, (IMP)swz_AVPI_playerItemWithURL); }
        }
        Class AVURLA = NSClassFromString(@"AVURLAsset");
        if (AVURLA) {
            Method m3 = class_getInstanceMethod(AVURLA, @selector(initWithURL:options:));
            if (m3) { orig_AVURLA_initWithURL = (void *)method_getImplementation(m3);
                      method_setImplementation(m3, (IMP)swz_AVURLA_initWithURL); }
            Method m4 = class_getClassMethod(AVURLA, @selector(URLAssetWithURL:options:));
            if (m4) { orig_AVURLA_assetWithURL = (void *)method_getImplementation(m4);
                      method_setImplementation(m4, (IMP)swz_AVURLA_assetWithURL); }
        }

        // WKWebView
        Class WK = NSClassFromString(@"WKWebView");
        if (WK) {
            Method m = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
            if (m) { orig_WK_init = (void *)method_getImplementation(m);
                     method_setImplementation(m, (IMP)swz_WK_init); }
        }

        // libcurl
        InstallCurlHook();

        ShowPopup(@"AliSniffer 已加载", @"已支持：URL + Headers 抓取（可直接粘贴到PC使用）");
        NSLog(@"[AliSniffer] ready.");
    }
}
