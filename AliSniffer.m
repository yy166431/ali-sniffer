//
// AliSniffer.m
// WKWebView-gated sniffer: only activates after opening target page.
// For authorized debugging on your own app/pages.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - ===== Config =====

// 你们页面的域名（命中后才启用）
static NSString * const kTargetHost = @"ced.wtyibxc.cn";

// 可选：也可以限制路径关键字（不需要就留空）
static inline BOOL MatchTargetPath(NSString *path) {
    if (!path.length) return YES;
    // 例：只在某个目录/接口页面启用
    // return [path containsString:@"/mag/livevideo/"];
    return YES;
}

// 命中后：是否弹提示/是否自动复制
static const BOOL kPopupOnHit = YES;
static const BOOL kCopyOnHit  = YES;

// 抓取哪些类型
static inline BOOL looksLikeInteresting(NSString *u){
    if (!u.length) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"] || [s containsString:@".flv"] || [s containsString:@".ts"] || [s containsString:@".mp4"]) return YES;
    if ([s containsString:@"auth"] || [s containsString:@"token"] || [s containsString:@"sign"] || [s containsString:@"txsecret"] || [s containsString:@"auth_key="]) return YES;
    return NO;
}

// 去重窗口（秒）
static const NSTimeInterval kDedupeWindow = 30.0;

// ⚠️ 可选：推送到你自家服务器（默认关闭）
// 你如果要开启，把 kEnablePush 改成 YES，并填你自己的地址/Token
static const BOOL kEnablePush = NO;
static NSString * const kPushHost  = @"http://127.0.0.1:8088";   // TODO: 改成你自己的
static NSString * const kPushToken = @"CHANGE_ME";              // TODO: 改成你自己的
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/push_raw", @"/push"]; }

#pragma mark - ===== Globals =====
static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static atomic_bool g_enabled = false;      // 命中目标页面后才 true
static atomic_bool g_hooksInstalled = false;

#pragma mark - ===== Helpers =====
static inline void on_main(void(^blk)(void)){
    if (!blk) return;
    if (NSThread.isMainThread) blk();
    else dispatch_async(dispatch_get_main_queue(), blk);
}

static NSString *jsonStringify(NSDictionary *obj){
    if (!obj) return nil;
    NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
}

static void _post_chain(NSArray<NSString*> *paths, NSUInteger idx, NSData *body){
    if (!kEnablePush) return;
    if (idx >= paths.count) return;
    NSString *url = [kPushHost stringByAppendingString:paths[idx]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    req.HTTPMethod = @"POST";
    [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
    req.HTTPBody = body;

    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, NSURLResponse *r, NSError *e){
        NSInteger sc = [r isKindOfClass:[NSHTTPURLResponse class]] ? ((NSHTTPURLResponse*)r).statusCode : -1;
        if (e || sc < 200 || sc >= 300) _post_chain(paths, idx+1, body);
    }] resume];
}

static void postText(NSString *text){
    if (!kEnablePush) return;
    if (!text.length) return;
    _post_chain(kPushPaths(), 0, [text dataUsingEncoding:NSUTF8StringEncoding]);
}

static BOOL dedupe_skip(NSString *u){
    if (!u.length) return YES;
    __block BOOL skip = NO;
    dispatch_sync(gq, ^{
        NSDate *last = g_seen[u];
        NSDate *now  = [NSDate date];
        if (last && [now timeIntervalSinceDate:last] < kDedupeWindow) skip = YES;
        else { g_seen[u] = now; skip = NO; }
    });
    return skip;
}

static void toast(NSString *msg){
    if (!kPopupOnHit) return;
    on_main(^{
        @try{
            UIWindow *w = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
            if (!w) return;

            UILabel *lab = [[UILabel alloc] initWithFrame:CGRectMake(16, 80, MIN(360, w.bounds.size.width-32), 70)];
            lab.numberOfLines = 0;
            lab.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.72];
            lab.textColor = UIColor.whiteColor;
            lab.font = [UIFont systemFontOfSize:12];
            lab.text = msg;
            lab.layer.cornerRadius = 10;
            lab.layer.masksToBounds = YES;
            [w addSubview:lab];

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [lab removeFromSuperview];
            });
        } @catch (__unused NSException *e) {}
    });
}

static BOOL isTargetURL(NSURL *u){
    if (!u) return NO;
    NSString *host = u.host.lowercaseString ?: @"";
    if (![host isEqualToString:kTargetHost.lowercaseString]) return NO;
    return MatchTargetPath(u.path ?: @"");
}

static void enableIfTarget(NSURL *u, NSString *from){
    if (!u) return;
    if (!isTargetURL(u)) return;

    bool expected = false;
    if (atomic_compare_exchange_strong(&g_enabled, &expected, true)) {
        NSString *msg = [NSString stringWithFormat:@"✅ Sniffer Enabled\n%@\n%@", from ?: @"", u.absoluteString ?: @""];
        NSLog(@"[ALI-WK] %@", msg);
        toast(msg);

        NSDictionary *evt = @{@"type":@"ENABLED",@"from":from?:@"", @"url":u.absoluteString?:@"", @"ts":@((long long)(NSDate.date.timeIntervalSince1970*1000))};
        NSString *s = jsonStringify(evt);
        if (s) postText(s);
    }
}

static void handleCapturedURL(NSString *url, NSString *from){
    if (!url.length) return;
    if (!atomic_load(&g_enabled)) return;          // 关键：未命中目标页面，不处理
    if (dedupe_skip(url)) return;

    NSLog(@"[ALI-WK][HIT][%@] %@", from ?: @"", url);

    if (looksLikeInteresting(url)) {
        if (kCopyOnHit) on_main(^{ @try{ UIPasteboard.generalPasteboard.string = url; }@catch(__unused NSException *e){} });
        if (kPopupOnHit) toast([NSString stringWithFormat:@"🎯 %@\n%@", from ?: @"HIT", url]);
    }

    NSDictionary *evt = @{@"type":@"HIT",@"from":from?:@"", @"url":url, @"ts":@((long long)(NSDate.date.timeIntervalSince1970*1000))};
    NSString *s = jsonStringify(evt);
    if (s) postText(s);
}

#pragma mark - ===== Hooks: WKWebView =====

static BOOL (*orig_WKWebView_loadRequest)(id, SEL, NSURLRequest*);
static BOOL replaced_WKWebView_loadRequest(id self, SEL _cmd, NSURLRequest *req){
    @try{
        NSURL *u = req.URL;
        if (u.absoluteString.length) {
            enableIfTarget(u, @"WKWebView loadRequest");
            if (atomic_load(&g_enabled)) handleCapturedURL(u.absoluteString, @"WK loadRequest");
        }
    } @catch(__unused NSException *e) {}
    return orig_WKWebView_loadRequest ? orig_WKWebView_loadRequest(self, _cmd, req) : ((BOOL(*)(id,SEL,NSURLRequest*))objc_msgSend)(self,_cmd,req);
}

// 一些 App 用 private 的 _loadRequest:
static void* (*orig_WKWebView__loadRequest)(id, SEL, NSURLRequest*, BOOL, id);
static void* replaced_WKWebView__loadRequest(id self, SEL _cmd, NSURLRequest *req, BOOL b, id i){
    @try{
        NSURL *u = req.URL;
        if (u.absoluteString.length) {
            enableIfTarget(u, @"WKWebView _loadRequest");
            if (atomic_load(&g_enabled)) handleCapturedURL(u.absoluteString, @"WK _loadRequest");
        }
    } @catch(__unused NSException *e) {}
    return orig_WKWebView__loadRequest ? orig_WKWebView__loadRequest(self,_cmd,req,b,i) : ((void*(*)(id,SEL,NSURLRequest*,BOOL,id))objc_msgSend)(self,_cmd,req,b,i);
}

#pragma mark - ===== Hooks: NSURLSession (only when enabled) =====
static NSURLSessionTask* (*orig_NSURLSession_dataTaskWithRequest)(id, SEL, NSURLRequest*);
static NSURLSessionTask* replaced_NSURLSession_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *req){
    @try{
        if (atomic_load(&g_enabled) && req.URL.absoluteString.length) {
            handleCapturedURL(req.URL.absoluteString, @"NSURLSession");
        }
    } @catch(__unused NSException *e) {}
    return orig_NSURLSession_dataTaskWithRequest ? orig_NSURLSession_dataTaskWithRequest(self,_cmd,req) : ((NSURLSessionTask*(*)(id,SEL,NSURLRequest*))objc_msgSend)(self,_cmd,req);
}

#pragma mark - ===== Install =====
static void install_hooks_once(void){
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_hooksInstalled, &expected, true)) return;

    @try{
        if (!gq) gq = dispatch_queue_create("com.ali.wk.gated", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];

        Class wk = NSClassFromString(@"WKWebView");
        if (wk) {
            Method m1 = class_getInstanceMethod(wk, @selector(loadRequest:));
            if (m1) {
                orig_WKWebView_loadRequest = (void*)method_getImplementation(m1);
                method_setImplementation(m1, (IMP)replaced_WKWebView_loadRequest);
                NSLog(@"[ALI-WK] hook WKWebView loadRequest installed");
            }

            SEL selPrivate = NSSelectorFromString(@"_loadRequest:shouldOpenExternalURLs:requestInitiatedByClient:");
            Method m2 = class_getInstanceMethod(wk, selPrivate);
            if (m2) {
                orig_WKWebView__loadRequest = (void*)method_getImplementation(m2);
                method_setImplementation(m2, (IMP)replaced_WKWebView__loadRequest);
                NSLog(@"[ALI-WK] hook WKWebView _loadRequest installed");
            }
        }

        // NSURLSession：只在 enabled 后才处理（函数内部判断），降低干扰
        Class s = NSClassFromString(@"NSURLSession");
        if (s) {
            Method ms = class_getInstanceMethod(s, @selector(dataTaskWithRequest:));
            if (ms) {
                orig_NSURLSession_dataTaskWithRequest = (void*)method_getImplementation(ms);
                method_setImplementation(ms, (IMP)replaced_NSURLSession_dataTaskWithRequest);
                NSLog(@"[ALI-WK] hook NSURLSession dataTaskWithRequest installed");
            }
        }

        NSDictionary *evt = @{@"type":@"LOADED",@"ts":@((long long)(NSDate.date.timeIntervalSince1970*1000)),
                              @"target":kTargetHost ?: @""};
        NSString *sjson = jsonStringify(evt);
        if (sjson) postText(sjson);
    } @catch(__unused NSException *e) {
        NSLog(@"[ALI-WK] install err: %@", e);
    }
}

__attribute__((constructor))
static void init_all(void){
    // 尽量晚一点安装，避免早期类未加载
    dispatch_async(dispatch_get_main_queue(), ^{
        install_hooks_once();
    });
}
