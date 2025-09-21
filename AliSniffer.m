//
//  AliSniffer_push_complete.m
//  完整可替换版本（包含抓取 + 弹窗复制 + 立即推送 + 每小时自动推送）
//  Build: ARC / iOS 12+
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <AVFoundation/AVFoundation.h>
#import <WebKit/WebKit.h>
#import <UIKit/UIKit.h>

#pragma mark - 配置

/// 推送目标
static NSString * const kPushEndpoint = @"http://139.155.57.242:8088/api/push_raw";
/// 令牌
static NSString * const kPushToken    = @"xZ7vN3qJc4G8f2K0bYw1sQp9LrT6D5aR";
/// 自动推送间隔（秒）= 1 小时
static const NSTimeInterval kPushInterval = 3600.0;

/// 是否开启弹窗（0 关闭 UI，1 开启 UI）
#ifndef SNIFFER_ENABLE_POPUP
#define SNIFFER_ENABLE_POPUP 1
#endif

/// 仅抓 RTMP/RTMPS + HTTP(s).flv
#ifndef SNIFFER_ONLY_FLV_RTMP
#define SNIFFER_ONLY_FLV_RTMP 1
#endif

#pragma mark - 工具

static NSString *_LatestURL = nil;

static dispatch_queue_t SnifferQueue(void) {
    static dispatch_queue_t q;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        q = dispatch_queue_create("com.kuniu.sniffer", DISPATCH_QUEUE_SERIAL);
    });
    return q;
}

static inline NSString *Lower(NSString *s) {
    return [s.lowercaseString stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

/// 判断是否目标直播流
static BOOL IsInterestingStream(NSString *url) {
    if (url.length == 0) return NO;
    NSString *lower = Lower(url);
#if SNIFFER_ONLY_FLV_RTMP
    if ([lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"]) return YES;
    if (([lower hasPrefix:@"http://"] || [lower hasPrefix:@"https://"]) &&
        [lower containsString:@".flv"]) return YES;
    return NO;
#else
    return ([lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
            [lower hasPrefix:@"ws://"]   || [lower hasPrefix:@"wss://"]   ||
            [lower containsString:@".flv"]);
#endif
}

static UIViewController *TopMostController(void) {
    UIWindow *keyWin = nil;
    if (@available(iOS 13.0, *)) {
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in scene.windows) {
                    if (w.isKeyWindow) { keyWin = w; break; }
                }
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
    if (url.length == 0) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *vc = TopMostController();
        if (!vc) return;
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:title
                                                                    message:url
                                                             preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"复制"
                                               style:UIAlertActionStyleDefault
                                             handler:^(__unused UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = url;
        }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
    });
#endif
}

static void UpdateLatestURL(NSString *url) {
    if (url.length == 0) return;
    dispatch_async(SnifferQueue(), ^{
        _LatestURL = [url copy];
    });
}

/// 立即推送最近 URL
static void PushLatestURL(void) {
    dispatch_async(SnifferQueue(), ^{
        NSString *u = _LatestURL;
        if (u.length == 0) return;

        NSMutableDictionary *payload = [@{
            @"token": kPushToken ?: @"",
            @"url"  : u ?: @"",
            @"ts"   : @((long long)([[NSDate date] timeIntervalSince1970])),
        } mutableCopy];

        NSString *bundle = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
        if (bundle.length) payload[@"bundle"] = bundle;

        NSURL *URL = [NSURL URLWithString:kPushEndpoint];
        if (!URL) return;

        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:URL];
        req.HTTPMethod = @"POST";
        req.timeoutInterval = 15;
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];

        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData * _Nullable data, NSURLResponse * _Nullable resp, NSError * _Nullable error) {
#ifdef DEBUG
            NSHTTPURLResponse *r = (NSHTTPURLResponse *)resp;
            NSLog(@"[Sniffer] push %@ -> %ld, err=%@", u, (long)r.statusCode, error);
#endif
        }] resume];
    });
}

static void CaptureAndHandleURL(NSString *url) {
    if (!IsInterestingStream(url)) return;
    UpdateLatestURL(url);
    ShowPopupIfNeeded(@"抓到直播流", url);
    PushLatestURL(); // 立即推送一次
}

#pragma mark - Swizzle 工具

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

#pragma mark - 1) NSURLSessionTask.resume

static IMP orig_NSURLSessionTask_resume = NULL;
static void snf_NSURLSessionTask_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *req = nil;
        if ([self respondsToSelector:NSSelectorFromString(@"currentRequest")]) {
            req = [self valueForKey:@"currentRequest"];
        }
        NSString *u = req.URL.absoluteString;
        if (IsInterestingStream(u)) {
            CaptureAndHandleURL(u);
        }
    } @catch (__unused NSException *e) {}
    ((void(*)(id,SEL))orig_NSURLSessionTask_resume)(self,_cmd);
}

#pragma mark - 2) NSURLProtocol（仅拦截 .flv http/https，并转发给系统）

static NSString * const kSnifferHandledKey = @"com.kuniu.sniffer.handled";

@interface SnifferURLProtocol : NSURLProtocol
@property (nonatomic, strong) NSURLSessionDataTask *task;
@end

@implementation SnifferURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if (!request) return NO;
    NSString *u = request.URL.absoluteString ?: @"";
    if (u.length == 0) return NO;

    // 只拦截 http/https 的 .flv
    NSString *lower = Lower(u);
    if (!([lower hasPrefix:@"http://"] || [lower hasPrefix:@"https://"])) return NO;
    if ([NSURLProtocol propertyForKey:kSnifferHandledKey inRequest:request]) return NO;
    if ([lower containsString:@".flv"]) return YES;
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];
    [NSURLProtocol setProperty:@(YES) forKey:kSnifferHandledKey inRequest:req];

    NSString *u = req.URL.absoluteString ?: @"";
    if (IsInterestingStream(u)) {
        CaptureAndHandleURL(u);
    }

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg delegate:nil delegateQueue:nil];

    __weak typeof(self) weakSelf = self;
    self.task = [session dataTaskWithRequest:req
                           completionHandler:^(NSData * _Nullable data,
                                               NSURLResponse * _Nullable response,
                                               NSError * _Nullable error) {
        __strong typeof(weakSelf) selfStrong = weakSelf;
        if (!selfStrong) return;
        if (error) {
            [selfStrong.client URLProtocol:selfStrong didFailWithError:error];
        } else {
            [selfStrong.client URLProtocol:selfStrong didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageAllowed];
            if (data.length) {
                [selfStrong.client URLProtocol:selfStrong didLoadData:data];
            }
            [selfStrong.client URLProtocolDidFinishLoading:selfStrong];
        }
    }];
    [self.task resume];
}

- (void)stopLoading {
    [self.task cancel];
    self.task = nil;
}

@end

#pragma mark - 3) CFReadStream（可选：这里不需要，留空即可）
// 如果以后你要补 CFReadStream hook，可在此补充。

#pragma mark - 4) AVPlayer / AVURLAsset

static IMP orig_AVPlayerItem_initWithURL = NULL;
static id snf_AVPlayerItem_initWithURL(id self, SEL _cmd, NSURL *URL) {
    if (IsInterestingStream(URL.absoluteString)) {
        CaptureAndHandleURL(URL.absoluteString);
    }
    return ((id(*)(id,SEL,NSURL *))orig_AVPlayerItem_initWithURL)(self,_cmd,URL);
}

static IMP orig_AVURLAsset_assetWithURL = NULL;
static id snf_AVURLAsset_assetWithURL(id cls, SEL _cmd, NSURL *URL) {
    if (IsInterestingStream(URL.absoluteString)) {
        CaptureAndHandleURL(URL.absoluteString);
    }
    return ((id(*)(id,SEL,NSURL *))orig_AVURLAsset_assetWithURL)(cls,_cmd,URL);
}

#pragma mark - 5) WKWebView（loadRequest 提示）

static IMP orig_WKWebView_loadRequest = NULL;
static id snf_WKWebView_loadRequest(id self, SEL _cmd, NSURLRequest *req) {
    NSString *u = req.URL.absoluteString ?: @"";
    if (IsInterestingStream(u)) {
        ShowPopupIfNeeded(@"命中可疑播放 URL", u);
        UpdateLatestURL(u);
    }
    return ((id(*)(id,SEL,NSURLRequest *))orig_WKWebView_loadRequest)(self,_cmd,req);
}

#pragma mark - 6) libcurl（此版本不包含，留空即可）
// 若未来需要 dlsym/curl hook，可在此加。

#pragma mark - 安装 Hook + 定时推送

__attribute__((constructor))
static void _sniffer_init(void) {
    @autoreleasepool {

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{

            // 注册 URLProtocol（仅拦截 .flv）
            [NSURLProtocol registerClass:[SnifferURLProtocol class]];

            // 1) NSURLSessionTask.resume
            Class taskCls = NSClassFromString(@"NSURLSessionTask");
            if (taskCls) {
                SwizzleInstance(taskCls, @selector(resume),
                                (IMP)snf_NSURLSessionTask_resume, &orig_NSURLSessionTask_resume);
            }

            // 4) AVPlayer / AVURLAsset
            Class itemCls = NSClassFromString(@"AVPlayerItem");
            if (itemCls) {
                SwizzleInstance(itemCls, @selector(initWithURL:),
                                (IMP)snf_AVPlayerItem_initWithURL, &orig_AVPlayerItem_initWithURL);
            }
            Class assetCls = NSClassFromString(@"AVURLAsset");
            if (assetCls) {
                SwizzleClass(assetCls, @selector(assetWithURL:),
                             (IMP)snf_AVURLAsset_assetWithURL, &orig_AVURLAsset_assetWithURL);
            }

            // 5) WKWebView
            Class wkCls = NSClassFromString(@"WKWebView");
            if (wkCls) {
                SwizzleInstance(wkCls, @selector(loadRequest:),
                                (IMP)snf_WKWebView_loadRequest, &orig_WKWebView_loadRequest);
            }

            // 定时推送（每 1 小时）
            [NSTimer scheduledTimerWithTimeInterval:kPushInterval repeats:YES
                                              block:^(__unused NSTimer * _Nonnull t) {
                PushLatestURL();
#if SNIFFER_ENABLE_POPUP
                ShowPopupIfNeeded(@"已加载", @"抓取 + 定时推送已启用");
#endif
            }];
        });
    }
}
