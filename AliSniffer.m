//
//  AliSniffer_push_complete.m  (v3 — 修复上传为 text/plain + X-Token)
//  变更点：按你的服务端要求：/api/push_raw 使用 text/plain 正文 + X-Token 头
//  并内置 /api/push_form (x-www-form-urlencoded) 兜底重试。
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <AVFoundation/AVFoundation.h>
#import <WebKit/WebKit.h>
#import <UIKit/UIKit.h>

#pragma mark - 配置

#ifndef SNIFFER_DEBUG_LOG
#define SNIFFER_DEBUG_LOG 0   // 抓不到/传不上时请开 1，看控制台
#endif

#ifndef SNIFFER_ENABLE_POPUP
#define SNIFFER_ENABLE_POPUP 1
#endif

#ifndef SNIFFER_ENABLE_URLPROTOCOL
#define SNIFFER_ENABLE_URLPROTOCOL 0  // 默认关闭，避免影响加载；确需再开
#endif

#ifndef SNIFFER_ONLY_FLV_RTMP
#define SNIFFER_ONLY_FLV_RTMP 1       // 仅抓 rtmp/rtmps 与 http(s).flv
#endif

static NSString * const kPushRawEndpoint  = @"http://139.155.57.242:8088/api/push_raw";
static NSString * const kPushFormEndpoint = @"http://139.155.57.242:8088/api/push_form";
static NSString * const kPushToken        = @"xZ7vN3qJc4G8f2K0bYw1sQp9LrT6D5aR";
static const NSTimeInterval kPushInterval = 3600.0; // 每小时自动推送

#pragma mark - 工具

static NSString *_LatestURL = nil;

static dispatch_queue_t SnifferQueue(void) {
    static dispatch_queue_t q;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ q = dispatch_queue_create("com.kuniu.sniffer", DISPATCH_QUEUE_SERIAL); });
    return q;
}

static inline NSString *Lower(NSString *s) {
    return [s.lowercaseString stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

static BOOL IsInterestingStream(NSString *url) {
    if (url.length == 0) return NO;
    NSString *lower = Lower(url);
#if SNIFFER_ONLY_FLV_RTMP
    if ([lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"]) return YES;
    if (([lower hasPrefix:@"http://"] || [lower hasPrefix:@"https://"]) && [lower containsString:@".flv"]) return YES;
    return NO;
#else
    if ([lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
        [lower hasPrefix:@"ws://"]   || [lower hasPrefix:@"wss://"]   ||
        [lower containsString:@".flv"]) return YES;
    return NO;
#endif
}

static UIViewController *TopMostController(void) {
    UIWindow *keyWin = nil;
    if (@available(iOS 13.0, *)) {
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in scene.windows) if (w.isKeyWindow) { keyWin = w; break; }
                if (keyWin) break;
            }
        }
    } else {
        keyWin = [UIApplication sharedApplication].keyWindow;
    }
    UIViewController *root = keyWin.rootViewController;
    while (root.presentedViewController) root = root.presentedViewController;
    return root;
}

static void ShowPopupIfNeeded(NSString *title, NSString *url) {
#if SNIFFER_ENABLE_POPUP
    if (!url.length) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *vc = TopMostController();
        if (!vc) return;
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:url preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction * _Nonnull a){ [UIPasteboard generalPasteboard].string = url; }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
    });
#endif
}

static void UpdateLatestURL(NSString *url) {
    if (!url.length) return;
    dispatch_async(SnifferQueue(), ^{
        _LatestURL = [url copy];
#if SNIFFER_DEBUG_LOG
        NSLog(@"[Sniffer] latest = %@", url);
#endif
    });
}

#pragma mark - 上传实现：先 push_raw(text/plain)；失败再 push_form(form-url-encoded)

static void PushLatestURL_FormFallback(NSString *u) {
    NSURL *URL = [NSURL URLWithString:kPushFormEndpoint];
    if (!URL) return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:URL];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 15;
    [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
    [req setValue:@"application/x-www-form-urlencoded; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    NSString *body = [NSString stringWithFormat:@"content=%@", [u stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLQueryAllowedCharacterSet]];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, NSURLResponse *r, NSError *e) {
#if SNIFFER_DEBUG_LOG
        NSHTTPURLResponse *resp = (NSHTTPURLResponse *)r;
        NSLog(@"[Sniffer] push_form -> %ld, err=%@", (long)resp.statusCode, e);
#endif
    }] resume];
}

static void PushLatestURL(void) {
    dispatch_async(SnifferQueue(), ^{
        NSString *u = _LatestURL;
        if (!u.length) return;

        NSURL *URL = [NSURL URLWithString:kPushRawEndpoint];
        if (!URL) return;
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:URL];
        req.HTTPMethod = @"POST";
        req.timeoutInterval = 15;
        [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
        [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = [u dataUsingEncoding:NSUTF8StringEncoding];

        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSHTTPURLResponse *resp = (NSHTTPURLResponse *)r;
#if SNIFFER_DEBUG_LOG
            NSLog(@"[Sniffer] push_raw -> %ld, err=%@", (long)resp.statusCode, e);
#endif
            // 非 2xx 或出错则兜底走 form
            if (e || resp.statusCode < 200 || resp.statusCode >= 300) {
                PushLatestURL_FormFallback(u);
            }
        }] resume];
    });
}

static void CaptureAndHandleURL(NSString *url) {
    if (!IsInterestingStream(url)) return;
    UpdateLatestURL(url);
    ShowPopupIfNeeded(@"抓到直播流", url);
    PushLatestURL(); // 立即推送一次
}

#pragma mark - Swizzle Helper

static void SwizzleInstance(Class c, SEL sel, IMP newImp, IMP __unsafe_unretained *store) {
    if (!c || !sel || !newImp) return;
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    if (store) *store = orig;
    method_setImplementation(m, newImp);
}

static void SwizzleClass(Class c, SEL sel, IMP newImp, IMP __unsafe_unretained *store) {
    if (!c || !sel || !newImp) return;
    Class meta = object_getClass(c);
    Method m = class_getClassMethod(c, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    if (store) *store = orig;
    class_replaceMethod(meta, sel, newImp, method_getTypeEncoding(m));
}

#pragma mark - 1) NSURLSessionTask.resume （全网扫）

static IMP g_orig_resume = NULL;

static void snf_task_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *req = nil;
        if ([self respondsToSelector:NSSelectorFromString(@"currentRequest")]) {
            req = [self valueForKey:@"currentRequest"];
        }
        NSString *u = req.URL.absoluteString ?: @"";
        if (IsInterestingStream(u)) {
            CaptureAndHandleURL(u);
        }
    } @catch (__unused NSException *e) {}
    ((void(*)(id,SEL))g_orig_resume)(self, _cmd);
}

static BOOL ClassIsKindOf(Class cls, Class base) {
    for (Class c = cls; c; c = class_getSuperclass(c)) {
        if (c == base) return YES;
    }
    return NO;
}

static void SwizzleAllTaskResume(void) {
    Class base = NSClassFromString(@"NSURLSessionTask");
    if (!base) return;

    int count = objc_getClassList(NULL, 0);
    Class *buffer = (Class *)malloc(sizeof(Class) * count);
    count = objc_getClassList(buffer, count);

    int hooked = 0;
    for (int i = 0; i < count; i++) {
        Class cls = buffer[i];
        if (!ClassIsKindOf(cls, base)) continue;
        SEL sel = @selector(resume);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) continue;

        IMP orig = method_getImplementation(m);
        if (!g_orig_resume) g_orig_resume = orig;
        method_setImplementation(m, (IMP)snf_task_resume);
        hooked++;
#if SNIFFER_DEBUG_LOG
        NSLog(@"[Sniffer] hook resume at class: %s", class_getName(cls));
#endif
    }
    free(buffer);
#if SNIFFER_DEBUG_LOG
    NSLog(@"[Sniffer] resume total hooked: %d", hooked);
#endif
}

#pragma mark - 4) AVPlayer / AVURLAsset

static IMP orig_AVPlayerItem_initWithURL = NULL;
static id snf_AVPlayerItem_initWithURL(id self, SEL _cmd, NSURL *URL) {
    if (IsInterestingStream(URL.absoluteString)) CaptureAndHandleURL(URL.absoluteString);
    return ((id(*)(id,SEL,NSURL *))orig_AVPlayerItem_initWithURL)(self,_cmd,URL);
}

static IMP orig_AVURLAsset_assetWithURL = NULL;
static id snf_AVURLAsset_assetWithURL(id cls, SEL _cmd, NSURL *URL) {
    if (IsInterestingStream(URL.absoluteString)) CaptureAndHandleURL(URL.absoluteString);
    return ((id(*)(id,SEL,NSURL *))orig_AVURLAsset_assetWithURL)(cls,_cmd,URL);
}

#pragma mark - 5) WKWebView loadRequest

static IMP orig_WKWebView_loadRequest = NULL;
static id snf_WKWebView_loadRequest(id self, SEL _cmd, NSURLRequest *req) {
    NSString *u = req.URL.absoluteString ?: @"";
    if (IsInterestingStream(u)) {
        ShowPopupIfNeeded(@"命中可疑播放 URL", u);
        UpdateLatestURL(u);
    }
    return ((id(*)(id,SEL,NSURLRequest *))orig_WKWebView_loadRequest)(self,_cmd,req);
}

#pragma mark - NSURLProtocol（默认关闭，必要时再开）

#if SNIFFER_ENABLE_URLPROTOCOL
static NSString * const kHandledKey = @"com.kuniu.sniffer.handled";

@interface SnifferURLProtocol : NSURLProtocol
@property (nonatomic, strong) NSURLSessionDataTask *task;
@end

@implementation SnifferURLProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *u = request.URL.absoluteString ?: @"";
    if (!u.length) return NO;
    NSString *l = Lower(u);
    if (!([l hasPrefix:@"http://"] || [l hasPrefix:@"https://"])) return NO;
    if ([NSURLProtocol propertyForKey:kHandledKey inRequest:request]) return NO;
    if ([l containsString:@".flv"]) return YES;
    return NO;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];
    [NSURLProtocol setProperty:@(YES) forKey:kHandledKey inRequest:req];
    NSString *u = req.URL.absoluteString ?: @"";
    if (IsInterestingStream(u)) CaptureAndHandleURL(u);

    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
    __weak typeof(self) w = self;
    self.task = [session dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e){
        __strong typeof(w) s = w;
        if (!s) return;
        if (e) [s.client URLProtocol:s didFailWithError:e];
        else {
            [s.client URLProtocol:s didReceiveResponse:r cacheStoragePolicy:NSURLCacheStorageAllowed];
            if (d.length) [s.client URLProtocol:s didLoadData:d];
            [s.client URLProtocolDidFinishLoading:s];
        }
    }];
    [self.task resume];
}
- (void)stopLoading { [self.task cancel]; self.task = nil; }
@end
#endif

#pragma mark - 初始化入口

__attribute__((constructor))
static void _sniffer_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{

#if SNIFFER_ENABLE_URLPROTOCOL
            [NSURLProtocol registerClass:[SnifferURLProtocol class]];
#if SNIFFER_DEBUG_LOG
            NSLog(@"[Sniffer] NSURLProtocol registered");
#endif
#endif

            // 全网扫 Hook
            SwizzleAllTaskResume();

            // AV 抓点
            Class itemCls = NSClassFromString(@"AVPlayerItem");
            if (itemCls) {
                SwizzleInstance(itemCls, @selector(initWithURL:), (IMP)snf_AVPlayerItem_initWithURL, &orig_AVPlayerItem_initWithURL);
#if SNIFFER_DEBUG_LOG
                NSLog(@"[Sniffer] hooked AVPlayerItem initWithURL:");
#endif
            }
            Class assetCls = NSClassFromString(@"AVURLAsset");
            if (assetCls) {
                SwizzleClass(assetCls, @selector(assetWithURL:), (IMP)snf_AVURLAsset_assetWithURL, &orig_AVURLAsset_assetWithURL);
#if SNIFFER_DEBUG_LOG
                NSLog(@"[Sniffer] hooked AVURLAsset assetWithURL:");
#endif
            }

            // WK 抓点
            Class wkCls = NSClassFromString(@"WKWebView");
            if (wkCls) {
                SwizzleInstance(wkCls, @selector(loadRequest:), (IMP)snf_WKWebView_loadRequest, &orig_WKWebView_loadRequest);
#if SNIFFER_DEBUG_LOG
                NSLog(@"[Sniffer] hooked WKWebView loadRequest:");
#endif
            }

            // 定时推送
            [NSTimer scheduledTimerWithTimeInterval:kPushInterval repeats:YES block:^(__unused NSTimer * _Nonnull t) {
                PushLatestURL();
#if SNIFFER_ENABLE_POPUP
                ShowPopupIfNeeded(@"已加载", @"抓取 + 定时推送启用");
#endif
            }];
        });
    }
}
