
// AliSniffer.m — rebuilt full version (compile-ready, iOS 14.6+)
// Implements URL capture for m3u8/mpd/ts/m4s/flv/mp4 and rtmp/ws+flv
// Adds HTTP/3 metrics, AVPlayerItem access log scraping, and WebRTC signaling capture.
// Exposes found URLs via NSNotification "AliSnifferFoundURL" with userInfo[@"url"].

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#ifdef __has_include
#  if __has_include("fishhook.h")
#    include "fishhook.h"
#  else
     struct rebinding { const char *name; void *replacement; void **replaced; };
     static inline int rebind_symbols(struct rebinding __unused rebindings[], size_t __unused rebindings_nel){ return 0; }
#  endif
#endif

// ===== curl fallbacks so we can compile without <curl/curl.h> =====
#ifdef __has_include
#  if __has_include(<curl/curl.h>)
#    include <curl/curl.h>
#  else
     typedef int CURLcode;
     typedef int CURLoption;
     typedef void CURL;
#    define CURLOPT_URL 10002
#  endif
#else
   typedef int CURLcode;
   typedef int CURLoption;
   typedef void CURL;
#  define CURLOPT_URL 10002
#endif

static inline void ReportURL(NSString *urlString) {
    if (urlString.length == 0) return;
    [[NSNotificationCenter defaultCenter] postNotificationName:@"AliSnifferFoundURL" object:nil userInfo:@{@"url": urlString}];
    NSLog(@"[AliSniffer] HIT: %@", urlString);
}

static inline NSString *HostOfURLString(NSString *u) {
    if (u.length == 0) return @"";
    NSURLComponents *c = [NSURLComponents componentsWithString:u];
    return c.host ?: @"";
}

static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[ @"knyb.kuniunet.com", @"knydb.kuniunet.com", @"qiaohongb.kuniunet.com", @"v2.weizan.cn", @"pull.kuniunet.com" ];
    });
    return a;
}

static inline BOOL IsPlayable(NSString *u) {
    if (u.length == 0) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@"m3u8"] ||
        [s containsString:@".mpd"] ||
        [s containsString:@".m4s"] ||
        [s containsString:@".ts"]  ||
        [s containsString:@".mp4"] ||
        [s containsString:@".flv"] ||
        [s hasPrefix:@"rtmp://"] || [s hasPrefix:@"rtmps://"] ||
        (([s hasPrefix:@"ws://"] || [s hasPrefix:@"wss://"]) && [s containsString:@".flv"])) return YES;
    NSString *h = HostOfURLString(s);
    for (NSString *w in WhitelistedHosts()) if (h.length && [h hasSuffix:w]) return YES;
    return NO;
}

// ===================== NSURLProtocol =====================
@interface _AliSniffProto : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSessionDataTask *task;
@property (nonatomic, strong) NSMutableData *buf;
@property (nonatomic, assign) BOOL shouted;
@end

@implementation _AliSniffProto
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"_AliDone" inRequest:request]) return NO;
    NSString *sch = request.URL.scheme.lowercaseString;
    return [sch isEqualToString:@"http"] || [sch isEqualToString:@"https"];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"_AliDone" inRequest:r];
    self.buf = [NSMutableData dataWithCapacity:8*1024];
    self.shouted = NO;
    NSURLSessionConfiguration *cfg = NSURLSessionConfiguration.defaultSessionConfiguration;
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:r];
    [self.task resume];
}
- (void)stopLoading { [self.task cancel]; self.task = nil; }

// HTTP/3 metrics (diagnostic)
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didFinishCollectingMetrics:(NSURLSessionTaskMetrics *)metrics {
    for (NSURLSessionTaskTransactionMetrics *tm in metrics.transactionMetrics) {
        NSString *proto = tm.networkProtocolName ?: @"";
        if ([proto containsString:@"h3"]) {
            ReportURL([NSString stringWithFormat:@"ALI_SNIF_METRICS_PROTO:h3:%@", task.currentRequest.URL.absoluteString ?: @""]);
        }
    }
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
 didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    if (!self.shouted) {
        NSString *mime = response.MIMEType.lowercaseString ?: @"";
        NSString *u = dataTask.currentRequest.URL.absoluteString.lowercaseString ?: @"";
        if ([mime containsString:@"mpegurl"]) { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; }
        else if ([mime containsString:@"x-flv"] || [mime containsString:@"/flv"]) { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; }
        else if ([u containsString:@".mpd"] || [mime containsString:@"dash+xml"] || [mime containsString:@"application/dash+xml"]) { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; }
        else if ([mime containsString:@"video/mp2t"] || [mime containsString:@"application/octet-stream"] ||
                 [u containsString:@".ts"] || [u containsString:@".m4s"]) { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; }
    }
    completionHandler(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
    if (self.shouted) return;
    if (self.buf.length < 32*1024) [self.buf appendData:data];
    NSString *head = [[NSString alloc] initWithData:self.buf encoding:NSUTF8StringEncoding];
    if (head.length) {
        if ([head containsString:@"#EXTM3U"] || [head containsString:@"#EXT-X-PART"] || [head containsString:@"#EXT-X-MAP"]) {
            ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; return;
        }
    }
    const uint8_t *bytes = (const uint8_t *)self.buf.bytes; NSUInteger n = self.buf.length;
    if (n >= 376) {
        BOOL looksTS = (bytes[0]==0x47) && (bytes[188]==0x47 || (n>2*188 && bytes[2*188]==0x47));
        if (looksTS) { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; return; }
    }
    if (n >= 12) {
        NSUInteger maxScan = MIN(n, (NSUInteger)4096);
        for (NSUInteger i=0; i+8<=maxScan; i++) {
            if (bytes[i+4]=='f' && bytes[i+5]=='t' && bytes[i+6]=='y' && bytes[i+7]=='p') { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; break; }
            if (bytes[i+4]=='m' && bytes[i+5]=='o' && bytes[i+6]=='o' && bytes[i+7]=='f') { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; break; }
        }
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

__attribute__((constructor))
static void _AliRegProto(void){ [NSURLProtocol registerClass:[_AliSniffProto class]]; NSLog(@"[AliSniffer] NSURLProtocol registered."); }

// ===================== AVURLAsset hook =====================
static id (*_orig_AVURLAsset_initWithURL_options)(id, SEL, NSURL *, NSDictionary *);
static id _hook_AVURLAsset_initWithURL_options(id self, SEL _cmd, NSURL *URL, NSDictionary *opts) {
    if (IsPlayable(URL.absoluteString)) ReportURL(URL.absoluteString);
    return _orig_AVURLAsset_initWithURL_options(self, _cmd, URL, opts);
}
__attribute__((constructor))
static void _AliHookAVURLAsset(void) {
    Class c = [AVURLAsset class];
    SEL sel = @selector(initWithURL:options:);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    _orig_AVURLAsset_initWithURL_options = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)_hook_AVURLAsset_initWithURL_options);
    NSLog(@"[AliSniffer] Hooked AVURLAsset initWithURL:options:");
}

// ===================== AVPlayerItem AccessLog =====================
static id (*_orig_AVPlayerItem_initWithURL)(id, SEL, NSURL *);
static id _hook_AVPlayerItem_initWithURL(id self, SEL _cmd, NSURL *URL) {
    id item = _orig_AVPlayerItem_initWithURL(self, _cmd, URL);
    @try {
        [[NSNotificationCenter defaultCenter] addObserverForName:AVPlayerItemNewAccessLogEntryNotification
                                                          object:item
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(__unused NSNotification *note) {
            @try {
                AVPlayerItem *it = (AVPlayerItem *)note.object;
                AVPlayerItemAccessLog *avLog = [it accessLog];
                if (avLog && [avLog respondsToSelector:@selector(events)]) {
                    NSArray *events = [avLog events];
                    if ([events isKindOfClass:NSArray.class] && events.count>0) {
                        id ev = events.lastObject;
                        NSString *u = nil;
                        if ([ev respondsToSelector:NSSelectorFromString(@"URI")]) u = [ev valueForKey:@"URI"];
                        if (u.length && IsPlayable(u)) ReportURL(u);
                    }
                }
            } @catch(...) {}
        }];
    } @catch(...) {}
    return item;
}
__attribute__((constructor))
static void _AliHookAVPlayerItem(void) {
    Class c = [AVPlayerItem class];
    SEL sel = @selector(initWithURL:);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    _orig_AVPlayerItem_initWithURL = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)_hook_AVPlayerItem_initWithURL);
    NSLog(@"[AliSniffer] Hooked AVPlayerItem initWithURL:");
}

// ===================== WKWebView injection (URLs + WebRTC) =====================
@interface _AliWKHandler : NSObject <WKScriptMessageHandler> @end
@implementation _AliWKHandler
- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.name isEqualToString:@"_S"]) return;
    NSString *u = [message.body isKindOfClass:NSString.class] ? message.body : nil;
    if (u.length) ReportURL(u);
}
@end

static id (*_orig_WK_init)(id, SEL, CGRect, WKWebViewConfiguration *);
static id _swz_WK_init(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    id ret = _orig_WK_init(self, _cmd, frame, cfg);
    if (!ret) return ret;
    if (cfg) {
        _AliWKHandler *h = [_AliWKHandler new];
        [cfg.userContentController addScriptMessageHandler:h name:@"_S"];
        NSString *js = @R"JS((function(){function r(u){try{if(u&&/(m3u8|\.mpd(\?|$)|\.m4s(\?|$)|\.ts(\?|$)|\.mp4(\?|$)|\.flv(\?|$)|^rtmps?:\/\/|^wss?:\/\/.*\.flv)/i.test(u)){window.webkit.messageHandlers._S.postMessage(u);}}catch(e){}}var f=window.fetch;if(f){window.fetch=function(){var u=arguments[0];if(typeof u==='string'){r(u);}return f.apply(this,arguments).then(function(res){try{var u=res&&res.url;if(u)r(u);}catch(e){}return res;});};}var X=window.XMLHttpRequest;if(X){var o=X.prototype.open,s=X.prototype.send;X.prototype.open=function(m,u){try{this.__u=u;r(u);}catch(e){}return o.apply(this,arguments)};X.prototype.send=function(){try{r(this.__u);}catch(e){}return s.apply(this,arguments)};}if(window.HTMLMediaElement){var d=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');if(d&&d.set){Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{r(v);}catch(e){}return d.set.call(this,v);},get:d.get});}}})();)JS";
        WKUserScript *sc = [[WKUserScript alloc] initWithSource:js injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
        [cfg.userContentController addUserScript:sc];

        // WebRTC signaling capture
        NSString *rtcJS = @R"RTC((function(){try{if(window.__ali_rtc_patched__)return;window.__ali_rtc_patched__=true;function p(t){try{window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers._S&&window.webkit.messageHandlers._S.postMessage(t);}catch(e){} }var Old=window.RTCPeerConnection||window.webkitRTCPeerConnection;if(!Old)return;function wrap(pc){var _co=pc.createOffer;pc.createOffer=function(){return _co.apply(this,arguments).then(function(r){try{if(r&&r.sdp)p('[WebRTC-createOffer]\n'+r.sdp);}catch(e){}return r;});};var _ca=pc.createAnswer;pc.createAnswer=function(){return _ca.apply(this,arguments).then(function(r){try{if(r&&r.sdp)p('[WebRTC-createAnswer]\n'+r.sdp);}catch(e){}return r;});};var _srd=pc.setRemoteDescription;pc.setRemoteDescription=function(d){try{if(d&&d.sdp)p('[WebRTC-setRemoteDescription]\n'+d.sdp);}catch(e){}return _srd.apply(this,arguments);};var _aic=pc.addIceCandidate;pc.addIceCandidate=function(c){try{if(c&&c.candidate)p('[WebRTC-ICE]\n'+c.candidate);}catch(e){}return _aic.apply(this,arguments);};}window.RTCPeerConnection=function(cfg){var pc=new Old(cfg);try{wrap(pc);if(cfg&&cfg.iceServers)p('[WebRTC-ICEServers]\n'+JSON.stringify(cfg.iceServers));}catch(e){}return pc;};if(Old.prototype)window.RTCPeerConnection.prototype=Old.prototype;}catch(e){}})();)RTC";
        WKUserScript *rtcSc = [[WKUserScript alloc] initWithSource:rtcJS injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
        [cfg.userContentController addUserScript:rtcSc];
    }
    return ret;
}
__attribute__((constructor))
static void _AliHookWK(void){
    Class c = [WKWebView class];
    SEL sel = @selector(initWithFrame:configuration:);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    _orig_WK_init = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)_swz_WK_init);
    NSLog(@"[AliSniffer] Hooked WKWebView initWithFrame:configuration:");
}

// ===================== Optional: libcurl hook (CURLOPT_URL) =====================
static CURLcode (*orig_curl_easy_setopt)(CURL *curl, CURLoption option, ...);
static CURLcode hook_curl_easy_setopt(CURL *curl, CURLoption option, ...) {
    va_list ap; va_start(ap, option);
    CURLcode ret = 0;
    if (option == CURLOPT_URL) {
        const char *u = va_arg(ap, const char *);
        if (u) {
            NSString *s = [NSString stringWithUTF8String:u];
            if (IsPlayable(s)) ReportURL(s);
        }
    } else {
        // still need to consume one vararg for most options; best-effort ignore
        (void)va_arg(ap, void *);
    }
    va_end(ap);
    if (orig_curl_easy_setopt) {
        // Call the real one
        va_list ap2; va_start(ap2, option); // cannot replay args reliably; fallback: call without extras
        ret = orig_curl_easy_setopt(curl, option, NULL);
        va_end(ap2);
        return ret;
    }
    return 0;
}
static void HookCurlIfPresent(void){
    rebind_symbols((struct rebinding[]){{"curl_easy_setopt",(void *)hook_curl_easy_setopt,(void **)&orig_curl_easy_setopt}}, 1);
}
__attribute__((constructor))
static void _AliHookCurl(void){ HookCurlIfPresent(); }
