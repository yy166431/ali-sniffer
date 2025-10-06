// ALIWeChatWKSniffer.m
// 注入微信中的 WKWebView，向页面注入 JS，捕获真实播放 URL（XHR/fetch/video.src）
// 仅做被动观测：命中后复制 & 弹窗 & 上报到你的服务器
// 编译为 dylib，注入微信（com.tencent.xin / WeChat）即可。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

#pragma mark - 可调参数 / 开关

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/api/push_form", @"/push", @"/push_raw"]; }

static const NSTimeInterval kFirstDelay     = 2.0;   // 首次延迟注入
static const NSTimeInterval kScanInterval   = 1.5;   // 扫描 WKWebView 的间隔
static const NSTimeInterval kDedupeWindow   = 60.0;  // 去重窗口
static const BOOL kShowPopupOnHit           = YES;   // 命中时弹窗 & 复制

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[ALI-WX] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#pragma mark - 全局状态

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static BOOL g_started = NO;

#pragma mark - 工具

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

static BOOL looksLikeStream(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"]||[s containsString:@".flv"]||[s containsString:@".mp4"]||
        [s containsString:@".ts"]  ||[s hasPrefix:@"rtmp://"]) return YES;
    if ([s containsString:@"phonelive"]||[s containsString:@"vzan"]||[s containsString:@"weizan"]||
        [s containsString:@"pull."]||[s containsString:@"replay"]||[s containsString:@"live"]) return YES;
    if ([s containsString:@"auth_key="]||[s containsString:@"txsecret"]||[s containsString:@"txkey"]||
        [s containsString:@"token="]||[s containsString:@"sign="]||[s containsString:@"auth="]) return YES;
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
    if (dedupe_skip(u)) { LOG(@"dedupe: %@", u); return; }
    LOG(@"HIT [%@] from %@", u, from);
    if (kShowPopupOnHit){
        UIPasteboard.generalPasteboard.string = u;
        popup(@"抓到URL", [NSString stringWithFormat:@"%@\n%@", from?:@"inpage", u], u);
    }
    postText(u);
}

#pragma mark - JS Payload

static NSString *inpageJS(void){
    // JS：hook XHR/fetch/<video>/<audio>，命中后通过 webkit.messageHandlers.__ALI_SNIF__ 回传
    return @
    "(function(){try{"
      "if(window.__ALI_SNIF_INJECTED__)return;window.__ALI_SNIF_INJECTED__=true;"
      "function L(u){if(!u)return false;u=u.toLowerCase();"
        "if(u.indexOf('.m3u8')!=-1||u.indexOf('.flv')!=-1||u.indexOf('.ts')!=-1||u.indexOf('.mp4')!=-1)return true;"
        "if(u.indexOf('auth_key=')!=-1||u.indexOf('txsecret')!=-1||u.indexOf('txkey')!=-1||u.indexOf('token=')!=-1||u.indexOf('sign=')!=-1||u.indexOf('auth=')!=-1)return true;"
        "if(u.indexOf('phonelive')!=-1||u.indexOf('vzan')!=-1||u.indexOf('weizan')!=-1||u.indexOf('pull.')!=-1||u.indexOf('replay')!=-1||u.indexOf('live')!=-1)return true;"
        "return false;}"
      "function N(u,f){try{var p={url:u,from:f||'inpage',ts:Date.now()};"
        "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.__ALI_SNIF__){window.webkit.messageHandlers.__ALI_SNIF__.postMessage(p);}else{console.log('[ALI_SNIF]',p);window.__ALI_SNIF_LAST__=p;}}catch(e){}}"
      // XHR
      "(function(){var O=XMLHttpRequest.prototype.open,S=XMLHttpRequest.prototype.send;"
        "XMLHttpRequest.prototype.open=function(m,u){try{this.__u=u?u.toString():'';}catch(e){}return O.apply(this,arguments)};"
        "XMLHttpRequest.prototype.send=function(b){try{var self=this,u=self.__u||'';if(L(u))N(u,'xhr:req');"
          "var onload=function(){try{var ct=(self.getResponseHeader?self.getResponseHeader('Content-Type'):'')||'';"
            "if(ct.toLowerCase().indexOf('mpegurl')!=-1||(self.responseText&&self.responseText.indexOf('#EXTM3U')!=-1))N(u,'xhr:m3u8');}catch(e){}};"
          "this.addEventListener&&this.addEventListener('load',onload);}catch(e){}return S.apply(this,arguments)};"
      "})();"
      // fetch
      "(function(){if(!window.fetch)return;var F=window.fetch;window.fetch=function(i,init){try{var u=(typeof i==='string')?i:(i&&i.url)||'';if(L(u))N(u,'fetch:req');"
        "return F.apply(this,arguments).then(function(r){try{var ct=r.headers&&r.headers.get&&r.headers.get('content-type')||'';"
          "if(ct&&ct.toLowerCase().indexOf('mpegurl')!=-1)N(u,'fetch:m3u8');else{var c=r.clone&&r.clone();if(c&&c.text)c.text().then(function(t){if(t&&t.indexOf('#EXTM3U')!=-1)N(u,'fetch:m3u8-text');}).catch(function(){});}}catch(e){}return r;});}"
        "catch(e){return F.apply(this,arguments)}})();"
      // media
      "(function(){function I(el,ev){try{var s=el.currentSrc||el.src||((el.querySelector&&el.querySelector('source'))||{}).src||'';if(s&&L(s))N(s,'media:'+ev);}catch(e){}}"
        "var obs=new MutationObserver(function(a){a.forEach(function(m){if(m.addedNodes){for(var i=0;i<m.addedNodes.length;i++){var n=m.addedNodes[i];"
          "if(n&&n.tagName&&(n.tagName.toLowerCase()==='video'||n.tagName.toLowerCase()==='audio')){I(n,'add');n.addEventListener&&n.addEventListener('play',function(){I(n,'play')},false);}else if(n&&n.querySelectorAll){var vs=n.querySelectorAll('video,audio');for(var j=0;j<vs.length;j++){I(vs[j],'sub');vs[j].addEventListener&&vs[j].addEventListener('play',function(){I(this,'play')},false);}}}}});});"
        "obs.observe(document.documentElement||document.body,{childList:true,subtree:true});"
        "var vs=document.querySelectorAll&&document.querySelectorAll('video,audio');for(var k=0;k<(vs?vs.length:0);k++){I(vs[k],'init');vs[k].addEventListener&&vs[k].addEventListener('play',function(){I(this,'play')},false);} "
        "var setA=Element.prototype.setAttribute;Element.prototype.setAttribute=function(k,v){try{if(this.tagName&&(this.tagName.toLowerCase()==='video'||this.tagName.toLowerCase()==='audio')&&k&&k.toLowerCase()==='src'){if(L(v))N(v,'setAttr');}}catch(e){}return setA.apply(this,arguments)};"
      "})();"
      "console.log('[ALI_SNIF] injected');"
    "}catch(e){console.log('[ALI_SNIF] inject error',e)}})();";
}

#pragma mark - JS Bridge

@interface ALIMessageHandler : NSObject <WKScriptMessageHandler>
@end
@implementation ALIMessageHandler
- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    @try{
        id body = message.body;
        if (![body isKindOfClass:[NSDictionary class]]) return;
        NSString *url  = body[@"url"];
        NSString *from = body[@"from"] ?: @"inpage";
        dispatch_async(gq, ^{ handleURL(url, [NSString stringWithFormat:@"WKInpage(%@)", from]); });
    }@catch(__unused NSException *e){}
}
@end

static ALIMessageHandler *g_handler;

#pragma mark - 注入与扫描

static const void *kInjectedKey = &kInjectedKey;

static void inject_into_webview(WKWebView *wv){
    if (!wv) return;
    @try{
        NSNumber *flag = objc_getAssociatedObject(wv, kInjectedKey);
        if (flag.boolValue) return; // 已注入
        objc_setAssociatedObject(wv, kInjectedKey, @(YES), OBJC_ASSOCIATION_RETAIN_NONATOMIC);

        // 注册 message handler（只需一次）
        if (!g_handler) g_handler = [ALIMessageHandler new];
        @try{
            [wv.configuration.userContentController addScriptMessageHandler:g_handler name:@"__ALI_SNIF__"];
        }@catch(__unused NSException *e){}

        NSString *js = inpageJS();
        [wv evaluateJavaScript:js completionHandler:^(id r, NSError *err){
            if (err) LOG(@"evaluate JS error: %@", err);
            else     LOG(@"evaluate JS OK");
        }];
    }@catch(__unused NSException *e){}
}

static void walk_view(UIView *v){
    if (!v) return;
    @try{
        Class WK = NSClassFromString(@"WKWebView");
        if (WK && [v isKindOfClass:WK]){
            inject_into_webview((WKWebView *)v);
        }
        for (UIView *sub in v.subviews) walk_view(sub);
    }@catch(__unused NSException *e){}
}

static void scan_loop(void){
    on_main(^{
        @try{
            for (UIWindow *w in UIApplication.sharedApplication.windows){
                walk_view(w);
            }
        }@catch(__unused NSException *e){}
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kScanInterval*NSEC_PER_SEC)), gq, ^{ scan_loop(); });
}

#pragma mark - 入口（延迟启动，主线程）

__attribute__((constructor))
static void ALIWeChatWKSnifferInit(void){
    @try{
        if (g_started) return;
        g_started = YES;
        if (!gq)    gq    = dispatch_queue_create("com.aliwechat.wksniffer", DISPATCH_QUEUE_SERIAL);
        if (!g_seen)g_seen= [NSMutableDictionary dictionary];

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kFirstDelay*NSEC_PER_SEC)),
                       gq, ^{
            LOG(@"start scanning WKWebView");
            scan_loop();
        });
    }@catch(__unused NSException *e){}
}
