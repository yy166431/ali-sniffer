// AliSniffer.m —— iOS14 实机抓取播放源（只提示 m3u8/mp4/白名单域名）
// 覆盖点：AliPlayer / NSURLSession / NSURLProtocol(MIME/#EXTM3U)
//       CFReadStream(fishhook) / AVPlayer(AVPlayerItem/AVURLAsset)
//       WKWebView(JS：fetch/XHR/video.src) / libcurl(CURLOPT_URL)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <WebKit/WebKit.h>
#import "fishhook.h"

#pragma mark - 配置：黑白名单

// ❌ 不提示的“噪声”域名/路径（日志/心跳/埋点等）
static NSArray<NSString *> *BlockedSubstrings(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"log.aliyuncs.com/logstores", // 阿里日志
            @"/beacon", @"/collect", @"/monitor", @"/log", @"umeng", @"bugly"
        ];
    });
    return a;
}

// ✅ 即使没有后缀，也提示的“可疑播放域名”（你可继续加）
static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"knydb.kuniunet.com",
            @"v2.weizan.cn"
        ];
    });
    return a;
}

#pragma mark - 弹窗 & 过滤

static void ShowPopup(NSString *title, NSString *msg) {
    if (msg.length == 0) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = msg;
        }]];
        [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *win = UIApplication.sharedApplication.keyWindow;
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

    // 明确后缀
    if ([lower containsString:@"m3u8"] || [lower containsString:@".mp4"]) return YES;

    // 白名单域名（即使没有后缀也提示）
    NSString *host = HostFromString(lower);
    for (NSString *h in WhitelistedHosts()) {
        if ([host hasSuffix:h]) return YES;
    }
    return NO;
}

// 10 秒去重，避免重复弹
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

static void ReportURL(NSString *url, NSString *from) {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;

    // 过滤噪声
    if (IsNoiseURL(lower)) {
        NSLog(@"[AliSniffer] ignore noise: %@", url);
        return;
    }

    // 只对“可播放”的 URL 提示
    if (!IsPlayableURL(url)) return;
    if (SeenRecently(url, 10.0)) return;

    if ([lower containsString:@"m3u8"]) {
        NSLog(@"[AliSniffer] M3U8(%@): %@", from, url);
        ShowPopup(@"抓到 M3U8", url);
    } else if ([lower containsString:@".mp4"]) {
        NSLog(@"[AliSniffer] MP4(%@): %@", from, url);
        ShowPopup(@"抓到 MP4", url);
    } else {
        // 白名单命中但无后缀
        NSLog(@"[AliSniffer] Whitelist(%@): %@", from, url);
        ShowPopup(@"命中可疑播放 URL", url);
    }
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

#pragma mark - ① AliPlayer / AliyunVodPlayer

static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    NSString *u = ExtractURLStringFromObj(source);
    if (u.length) ReportURL(u, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

static int (*orig_Ali_prepareURL)(id, SEL, NSString *);
static int swz_Ali_prepareURL(id self, SEL _cmd, NSString *url) {
    if (url.length) ReportURL(url, @"AliyunVodPlayer.prepareWithURL");
    return orig_Ali_prepareURL(self, _cmd, url);
}

static int (*orig_Ali_playURL)(id, SEL, NSString *);
static int swz_Ali_playURL(id self, SEL _cmd, NSString *url) {
    if (url.length) ReportURL(url, @"AliyunVodPlayer.play");
    return orig_Ali_playURL(self, _cmd, url);
}

#pragma mark - ② NSURLSessionTask.resume

static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if ([self respondsToSelector:@selector(currentRequest)]) {
            NSURLRequest *req = [self performSelector:@selector(currentRequest)];
            if ([req isKindOfClass:NSURLRequest.class] && req.URL) {
                ReportURL(req.URL.absoluteString, @"NSURLSessionTask.resume");
            }
        }
    } @catch (...) {}
    orig_task_resume(self, _cmd);
}

#pragma mark - ③ NSURLProtocol（识别 MIME / #EXTM3U）

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
        NSString *mime = response.MIMEType.lowercaseString;
        if ([mime containsString:@"mpegurl"]) {
            ReportURL(dataTask.currentRequest.URL.absoluteString, @"NSURLProtocol(MIME)");
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
            ReportURL(dataTask.currentRequest.URL.absoluteString, @"NSURLProtocol(#EXTM3U)");
            self.shouted = YES;
        }
    }
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

// 注入 Protocol
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

#pragma mark - ④ CFReadStream Hook

typedef CFURLRef (*PFN_CFHTTPMessageCopyRequestURL)(CFHTTPMessageRef);
static PFN_CFHTTPMessageCopyRequestURL p_CFHTTPMessageCopyRequestURL = NULL;

typedef CFReadStreamRef (*PFN_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static PFN_CFReadStreamCreateForHTTPRequest orig_CFReadStreamCreateForHTTPRequest = NULL;

static CFReadStreamRef hook_CFReadStreamCreateForHTTPRequest(CFAllocatorRef a, CFHTTPMessageRef req) {
    if (req && p_CFHTTPMessageCopyRequestURL) {
        CFURLRef u = p_CFHTTPMessageCopyRequestURL(req);
        if (u) {
            NSString *url = [(__bridge NSURL *)u absoluteString];
            if (url.length) ReportURL(url, @"CFReadStreamCreateForHTTPRequest");
        }
    }
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(a, req) : NULL;
}

#pragma mark - ⑤ AVPlayer / AVURLAsset

static id (*orig_AVPI_initWithURL)(id, SEL, NSURL *);
static id swz_AVPI_initWithURL(id self, SEL _cmd, NSURL *url) {
    if (url) ReportURL(url.absoluteString, @"AVPlayerItem.initWithURL");
    return orig_AVPI_initWithURL(self, _cmd, url);
}

static id (*orig_AVPI_playerItemWithURL)(id, SEL, NSURL *);
static id swz_AVPI_playerItemWithURL(id self, SEL _cmd, NSURL *url) {
    if (url) ReportURL(url.absoluteString, @"AVPlayerItem.playerItemWithURL");
    return orig_AVPI_playerItemWithURL(self, _cmd, url);
}

static id (*orig_AVURLA_initWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_initWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) {
    if (url) ReportURL(url.absoluteString, @"AVURLAsset.initWithURL");
    return orig_AVURLA_initWithURL(self, _cmd, url, opt);
}

static id (*orig_AVURLA_assetWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_assetWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) {
    if (url) ReportURL(url.absoluteString, @"AVURLAsset.assetWithURL");
    return orig_AVURLA_assetWithURL(self, _cmd, url, opt);
}

#pragma mark - ⑥ WKWebView 注入 JS（抓 H5）

@interface AliWKHandler : NSObject<WKScriptMessageHandler>
@end
@implementation AliWKHandler
- (void)userContentController:(WKUserContentController *)uc didReceiveScriptMessage:(WKScriptMessage *)m {
    if ([m.name isEqualToString:@"AliSniffer"]) {
        NSString *url = [m.body isKindOfClass:NSString.class] ? (NSString *)m.body : @"";
        if (url.length) ReportURL(url, @"WKWebView(JS)");
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
          "function report(u){try{if(u&&/m3u8|\\.mp4(\\?|$)/i.test(u)){window.webkit.messageHandlers.AliSniffer.postMessage(u);}}catch(e){}}"
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

#pragma mark - ⑦ libcurl：CURLOPT_URL

typedef int CURLcode;
static CURLcode (*orig_curl_easy_setopt)(void *curl, int option, ...);

static CURLcode hook_curl_easy_setopt(void *curl, int option, ...) {
    va_list ap; va_start(ap, option);

    if (option == 10002 /* CURLOPT_URL */) {
        const char *c_url = va_arg(ap, const char *);
        if (c_url) {
            NSString *url = [NSString stringWithUTF8String:c_url];
            if (url.length) ReportURL(url, @"curl_easy_setopt(CURLOPT_URL)");
        }
        va_end(ap);
        va_start(ap, option);
        (void)va_arg(ap, const char *);
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

        // NSURLSessionTask
        Class Task = NSClassFromString(@"NSURLSessionTask");
        if (Task && class_getInstanceMethod(Task, @selector(resume))) {
            Swz(Task, @selector(resume), (IMP)swz_task_resume, (IMP *)&orig_task_resume);
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

        // CFReadStream hook（运行时解析符号）
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

        // WKWebView 注入
        Class WK = NSClassFromString(@"WKWebView");
        if (WK) {
            Method m = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
            if (m) { orig_WK_init = (void *)method_getImplementation(m);
                     method_setImplementation(m, (IMP)swz_WK_init); }
        }

        // libcurl hook
        InstallCurlHook();

        ShowPopup(@"AliSniffer 已加载", @"只提示 m3u8/mp4/白名单域名");
        NSLog(@"[AliSniffer] ready.");
    }
}
