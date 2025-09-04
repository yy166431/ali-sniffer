// AliSniffer.m — 非越狱精简版（iOS 12+）
// 目标：稳定抓取播放 URL + 轻量悬浮球，不依赖 CoreGraphics，自带可用性保护。
// Hook：NSURLSessionTask.resume / NSURLProtocol(MIME & #EXTM3U) / AVPlayerItem & AVURLAsset / WKWebView(JS) / libcurl(CURLOPT_URL)

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// 可选：如果你的工程里已有 fishhook.h/c，保持一致的包含路径即可
#import "fishhook.h"

// ===================== 配置 =====================

// 白名单（没有明显后缀也要提示）
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

// 噪声（不提示）
static NSArray<NSString *> *BlockedSubstrings(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"log.aliyuncs.com/logstores",
            @"/beacon", @"/collect", @"/monitor", @"/log", @"umeng", @"bugly"
        ];
    });
    return a;
}

// 是否启用悬浮球（仅 UIKit 默认组件）
#define ENABLE_FLOAT_BALL 1

// 最近保存的条数
#define MAX_RECENT 50

// ===================== 工具 & UI =====================

static NSMutableArray<NSString *> *g_recentList;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;

static void run_on_main(void (^blk)(void)) {
    if (!blk) return;
    if ([NSThread isMainThread]) blk();
    else dispatch_async(dispatch_get_main_queue(), blk);
}

static NSString *HostOf(NSString *s) {
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.lowercaseString ?: @"";
}

static BOOL isNoise(NSString *lower) {
    for (NSString *k in BlockedSubstrings()) {
        if ([lower containsString:k]) return YES;
    }
    return NO;
}

static BOOL isPlayable(NSString *url) {
    if (url.length == 0) return NO;
    NSString *lower = url.lowercaseString;
    if ([lower containsString:@"m3u8"] ||
        [lower containsString:@".mp4"] ||
        [lower containsString:@".flv"] ||
        [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
        (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        return YES;
    }
    NSString *host = HostOf(lower);
    for (NSString *h in WhitelistedHosts()) {
        if ([host hasSuffix:h]) return YES;
    }
    return NO;
}

static BOOL seenRecently(NSString *key, NSTimeInterval sec) {
    static dispatch_once_t once; dispatch_once(&once, ^{ g_seen = [NSMutableDictionary dictionary]; });
    NSDate *now = [NSDate date];
    NSDate *last = g_seen[key];
    if (last && [now timeIntervalSinceDate:last] < sec) return YES;
    g_seen[key] = now;
    if (g_seen.count > 200) [g_seen removeAllObjects];
    return NO;
}

static void showAlert(NSString *title, NSString *msg) {
    if (msg.length == 0) return;
    run_on_main(^{
        UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        if (!win) return;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;

        UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = msg;
        }]];
        [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:a animated:YES completion:nil];
    });
}

static void recordURL(NSString *u) {
    if (!u.length) return;
    static dispatch_once_t once; dispatch_once(&once, ^{ g_recentList = [NSMutableArray array]; });
    // 去重插入
    @synchronized (g_recentList) {
        [g_recentList removeObject:u];
        [g_recentList insertObject:u atIndex:0];
        if (g_recentList.count > MAX_RECENT) [g_recentList removeLastObject];
    }
}

static void reportURL(NSString *url, NSString *from) {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;
    if (isNoise(lower)) return;
    if (!isPlayable(url)) return;
    if (seenRecently(url, 6.0)) return;

    recordURL(url);

    if ([lower containsString:@"m3u8"]) {
        NSLog(@"[AliSniffer] M3U8(%@): %@", from, url);
        showAlert(@"抓到 M3U8", url);
    } else if ([lower containsString:@".mp4"]) {
        NSLog(@"[AliSniffer] MP4(%@): %@", from, url);
        showAlert(@"抓到 MP4", url);
    } else if ([lower containsString:@".flv"] ||
               [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
               (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        NSLog(@"[AliSniffer] FLV/RTMP(%@): %@", from, url);
        showAlert(@"抓到直播流 (FLV/RTMP)", url);
    } else {
        NSLog(@"[AliSniffer] White(%@): %@", from, url);
        showAlert(@"命中可疑播放 URL", url);
    }
}

// ===================== 悬浮球（超轻量） =====================

#if ENABLE_FLOAT_BALL
@interface ASFloatBall : UIWindow
@end
@implementation ASFloatBall
- (instancetype)init {
    self = [super initWithFrame:CGRectMake(20, 150, 52, 52)];
    if (!self) return nil;
    self.windowLevel = UIWindowLevelAlert + 1;
    self.backgroundColor = [UIColor clearColor];
    self.hidden = NO;

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = self.bounds;
    btn.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    btn.layer.cornerRadius = 26;
    btn.clipsToBounds = YES;
    btn.backgroundColor = [UIColor colorWithWhite:0 alpha:0.5];
    [btn setTitle:@"源" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    [btn addTarget:self action:@selector(onTap) forControlEvents:UIControlEventTouchUpInside];
    [self addSubview:btn];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPan:)];
    [self addGestureRecognizer:pan];
    return self;
}
- (void)onTap {
    // 展示最近若干条
    NSMutableString *msg = [NSMutableString string];
    @synchronized (g_recentList) {
        NSInteger n = MIN(10, g_recentList.count);
        for (NSInteger i = 0; i < n; i++) {
            [msg appendFormat:@"%ld) %@\n\n", (long)(i+1), g_recentList[i]];
        }
    }
    if (msg.length == 0) [msg appendString:@"暂无记录"];
    showAlert(@"最近抓到的 URL（点复制可拷贝）", msg);
}
- (void)onPan:(UIPanGestureRecognizer *)gr {
    CGPoint t = [gr translationInView:self];
    self.center = CGPointMake(self.center.x + t.x, self.center.y + t.y);
    [gr setTranslation:CGPointZero inView:self];
}
@end
#endif

// ===================== Hook 实现 =====================

// 1) NSURLSessionTask.resume
static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if ([self respondsToSelector:@selector(currentRequest)]) {
            NSURLRequest *req = [self performSelector:@selector(currentRequest)];
            if ([req isKindOfClass:NSURLRequest.class] && req.URL) {
                reportURL(req.URL.absoluteString, @"NSURLSessionTask.resume");
            }
        }
    } @catch (...) {}
    orig_task_resume(self, _cmd);
}

// 2) NSURLProtocol：识别 MIME / #EXTM3U / x-flv
@interface ASURLProbe : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@property(nonatomic,strong) NSMutableData *buf;
@property(nonatomic,assign) BOOL shouted;
@end

@implementation ASURLProbe
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"ASProbeHandled" inRequest:request]) return NO;
    NSString *sch = request.URL.scheme.lowercaseString;
    return [sch isEqualToString:@"http"] || [sch isEqualToString:@"https"];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"ASProbeHandled" inRequest:r];
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
        if ([mime containsString:@"mpegurl"]) { // m3u8
            reportURL(dataTask.currentRequest.URL.absoluteString, @"NSURLProtocol(MIME-M3U8)");
            self.shouted = YES;
        } else if ([mime containsString:@"x-flv"] || [mime containsString:@"/flv"]) {
            reportURL(dataTask.currentRequest.URL.absoluteString, @"NSURLProtocol(MIME-FLV)");
            self.shouted = YES;
        }
    }
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
    if (!self.shouted && self.buf.length < 16384) {
        [self.buf appendData:data];
        NSString *head = [[NSString alloc] initWithData:self.buf encoding:NSUTF8StringEncoding];
        if (head && [head containsString:@"#EXTM3U"]) {
            reportURL(dataTask.currentRequest.URL.absoluteString, @"NSURLProtocol(#EXTM3U)");
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
    if (![arr containsObject:ASURLProbe.class]) [arr insertObject:ASURLProbe.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}
static NSURLSessionConfiguration* (*orig_ephCfg)(id, SEL);
static NSURLSessionConfiguration* swz_ephCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_ephCfg(self, _cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:ASURLProbe.class]) [arr insertObject:ASURLProbe.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}

// 3) AVPlayerItem / AVURLAsset
static id (*orig_AVPI_initWithURL)(id, SEL, NSURL *);
static id swz_AVPI_initWithURL(id self, SEL _cmd, NSURL *url) {
    if (url) reportURL(url.absoluteString, @"AVPlayerItem.initWithURL");
    return orig_AVPI_initWithURL(self, _cmd, url);
}
static id (*orig_AVPI_playerItemWithURL)(id, SEL, NSURL *);
static id swz_AVPI_playerItemWithURL(id self, SEL _cmd, NSURL *url) {
    if (url) reportURL(url.absoluteString, @"AVPlayerItem.playerItemWithURL");
    return orig_AVPI_playerItemWithURL(self, _cmd, url);
}
static id (*orig_AVURLA_initWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_initWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) {
    if (url) reportURL(url.absoluteString, @"AVURLAsset.initWithURL");
    return orig_AVURLA_initWithURL(self, _cmd, url, opt);
}
static id (*orig_AVURLA_assetWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_assetWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) {
    if (url) reportURL(url.absoluteString, @"AVURLAsset.assetWithURL");
    return orig_AVURLA_assetWithURL(self, _cmd, url, opt);
}

// 4) WKWebView 注入 JS（fetch / XHR / <video>.src）
@interface ASWKHandler : NSObject<WKScriptMessageHandler>
@end
@implementation ASWKHandler
- (void)userContentController:(id)uc didReceiveScriptMessage:(id)m {
    @try {
        if ([m isKindOfClass:NSClassFromString(@"WKScriptMessage")]) {
            NSString *name = [m valueForKey:@"name"];
            id body = [m valueForKey:@"body"];
            if ([name isEqual:@"ASnif"] && [body isKindOfClass:NSString.class]) {
                reportURL((NSString *)body, @"WKWebView(JS)");
            }
        }
    } @catch (...) {}
}
@end

static char kASWKHandlerKey;
static char kASWKUserScriptKey;

static id (*orig_WK_init)(id, SEL, CGRect, id);
static id swz_WK_init(id self, SEL _cmd, CGRect frame, id cfg) {
    // 运行时弱依赖，避免无 WebKit 环境崩溃
    Class WKUserContentController = NSClassFromString(@"WKUserContentController");
    Class WKUserScript = NSClassFromString(@"WKUserScript");

    if (cfg && WKUserContentController && WKUserScript) {
        id ucc = [cfg valueForKey:@"userContentController"];
        ASWKHandler *handler = [ASWKHandler new];
        objc_setAssociatedObject(cfg, &kASWKHandlerKey, handler, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [ucc performSelector:@selector(addScriptMessageHandler:name:) withObject:handler withObject:@"ASnif"];

        NSString *js =
        @"(function(){function r(u){try{if(u&&/(m3u8|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)/i.test(u)){window.webkit.messageHandlers.ASnif.postMessage(u);}}catch(e){}}"
         "var _f=window.fetch;if(_f){window.fetch=function(){var u=arguments[0];if(typeof u==='string'){r(u);}return _f.apply(this,arguments).then(function(res){try{var u=res&&res.url;if(u)r(u);}catch(e){}return res;});}}"
         "var X=window.XMLHttpRequest;if(X){var o=X.prototype.open,s=X.prototype.send;X.prototype.open=function(m,u){try{this.__u=u;r(u);}catch(e){}return o.apply(this,arguments)};X.prototype.send=function(){try{r(this.__u);}catch(e){}return s.apply(this,arguments)};}"
         "if(window.HTMLMediaElement){var d=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');if(d&&d.set){Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{r(v);}catch(e){}return d.set.call(this,v);},get:d.get});}}})();";

        id script = [[NSClassFromString(@"WKUserScript") alloc] init];
        script = [script initWithSource:js injectionTime:0 forMainFrameOnly:NO];
        [ucc performSelector:@selector(addUserScript:) withObject:script];
        objc_setAssociatedObject(cfg, &kASWKUserScriptKey, script, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return orig_WK_init(self, _cmd, frame, cfg);
}

// 5) libcurl：CURLOPT_URL
typedef int CURLcode;
static CURLcode (*orig_curl_easy_setopt)(void *curl, int option, ...);
static CURLcode hook_curl_easy_setopt(void *curl, int option, ...) {
    va_list ap; va_start(ap, option);
    if (option == 10002 /* CURLOPT_URL */) {
        const char *c_url = va_arg(ap, const char *);
        if (c_url) reportURL([NSString stringWithUTF8String:c_url], @"curl_easy_setopt(CURLOPT_URL)");
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

static void install_curl_hook(void) {
    struct rebinding rbs[] = {
        {"curl_easy_setopt", (void *)hook_curl_easy_setopt, (void **)&orig_curl_easy_setopt}
    };
    rebind_symbols(rbs, 1);
}

// ===================== 安装所有 Hook =====================

__attribute__((constructor))
static void _as_init(void) {
    @autoreleasepool {
        // NSURLSessionTask.resume
        Class Task = NSClassFromString(@"NSURLSessionTask");
        Method mResume = class_getInstanceMethod(Task, @selector(resume));
        if (Task && mResume) {
            orig_task_resume = (void *)method_getImplementation(mResume);
            method_setImplementation(mResume, (IMP)swz_task_resume);
        }

        // 注入 NSURLProtocol
        Class Cfg = NSURLSessionConfiguration.class;
        Method m1 = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
        if (m1) { orig_defCfg = (void *)method_getImplementation(m1);
                 method_setImplementation(m1, (IMP)swz_defCfg); }
        Method m2 = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
        if (m2) { orig_ephCfg = (void *)method_getImplementation(m2);
                 method_setImplementation(m2, (IMP)swz_ephCfg); }

        // AVPlayer / AVURLAsset
        Class AVPI = NSClassFromString(@"AVPlayerItem");
        if (AVPI) {
            Method a = class_getInstanceMethod(AVPI, @selector(initWithURL:));
            if (a) { orig_AVPI_initWithURL = (void *)method_getImplementation(a);
                     method_setImplementation(a, (IMP)swz_AVPI_initWithURL); }
            Method b = class_getClassMethod(AVPI, @selector(playerItemWithURL:));
            if (b) { orig_AVPI_playerItemWithURL = (void *)method_getImplementation(b);
                     method_setImplementation(b, (IMP)swz_AVPI_playerItemWithURL); }
        }
        Class AVURLA = NSClassFromString(@"AVURLAsset");
        if (AVURLA) {
            Method c = class_getInstanceMethod(AVURLA, @selector(initWithURL:options:));
            if (c) { orig_AVURLA_initWithURL = (void *)method_getImplementation(c);
                     method_setImplementation(c, (IMP)swz_AVURLA_initWithURL); }
            Method d = class_getClassMethod(AVURLA, @selector(URLAssetWithURL:options:));
            if (d) { orig_AVURLA_assetWithURL = (void *)method_getImplementation(d);
                     method_setImplementation(d, (IMP)swz_AVURLA_assetWithURL); }
        }

        // WKWebView（弱依赖）
        Class WK = NSClassFromString(@"WKWebView");
        if (WK) {
            Method m = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
            if (m) { orig_WK_init = (void *)method_getImplementation(m);
                     method_setImplementation(m, (IMP)swz_WK_init); }
        }

        // libcurl
        install_curl_hook();

#if ENABLE_FLOAT_BALL
        run_on_main(^{
            __unused ASFloatBall *ball = [ASFloatBall new];
        });
#endif
        showAlert(@"LiveHelper 已加载", @"已启用 URL 抓取与悬浮球（最多保留最近 50 条）");
        NSLog(@"[LiveHelper] ready.");
    }
}
