//
//  AliSniffer.m — iOS14 实机抓取播放源（m3u8/mp4/flv/rtmp + 自动补齐Headers + 白名单域名）
//  覆盖：AliPlayer / AliyunVodPlayer / NSURLSession(含Background) / NSURLProtocol(MIME/#EXTM3U/x-flv)
//       CFReadStream(fishhook) / AVPlayer(AVPlayerItem/AVURLAsset)
//       WKWebView(JS：fetch/XHR/video.src) / libcurl(CURLOPT_URL)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <WebKit/WebKit.h>
#import "fishhook.h"

#pragma mark - 配置：黑白名单

// ❌ 噪声（日志/心跳/监控等），不提示
static NSArray<NSString *> *BlockedSubstrings(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"log.aliyuncs.com/logstores",
            @"/beacon", @"/collect", @"/monitor", @"/log", @"umeng", @"bugly"
        ];
    });
    return a;
}

// ✅ 白名单：即使没有后缀也提示（可按需增加域名）
static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"knydb.kuniunet.com",
            @"knyb.kuniunet.com",
            @"qiaohongb.kuniunet.com",
            @"v2.weizan.cn"
        ];
    });
    return a;
}

#pragma mark - 弹窗 & 基础工具

static void ShowPopup(NSString *title, NSString *msg) {
    if (msg.length == 0) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = msg;
        }]];
        [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        [vc presentViewController:a animated:YES completion:nil];
    });
}

static NSString *HostFromString(NSString *s) {
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.lowercaseString ?: @"";
}

static BOOL IsNoiseURL(NSString *lower) {
    for (NSString *k in BlockedSubstrings()) {
        if ([lower containsString:k]) return YES;
    }
    return NO;
}

static BOOL IsPlayableURL(NSString *url) {
    if (url.length == 0) return NO;
    NSString *lower = url.lowercaseString;

    // 1) 明确后缀 / 协议
    if ([lower containsString:@"m3u8"] ||
        [lower containsString:@".mp4"] ||
        [lower containsString:@".flv"] ||                                 // HTTP-FLV
        [lower hasPrefix:@"rtmp://"]  || [lower hasPrefix:@"rtmps://"] ||  // RTMP
        (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"]) // WS-FLV
       ) {
        return YES;
    }

    // 2) 白名单域名（无后缀也提示）
    NSString *host = HostFromString(lower);
    for (NSString *h in WhitelistedHosts()) {
        if ([host hasSuffix:h]) return YES;
    }
    return NO;
}

// 10 秒去重，避免重复弹
static NSMutableDictionary<NSString*, NSDate*> *g_recent;
static BOOL SeenRecently(NSString *key, NSTimeInterval sec) {
    static dispatch_once_t once; dispatch_once(&once, ^{ g_recent = [NSMutableDictionary dictionary]; });
    NSDate *now = [NSDate date];
    NSDate *last = g_recent[key];
    if (last && [now timeIntervalSinceDate:last] < sec) return YES;
    g_recent[key] = now;
    if (g_recent.count > 300) [g_recent removeAllObjects];
    return NO;
}

#pragma mark - 按域名缓存 Headers（用于只有URL时“推测Headers”）

static NSMutableDictionary<NSString*, NSDictionary*> *g_hostHeaders;

// 更新/合并并缓存某域名的头
static void AS_CacheHeadersForHost(NSString *host, NSDictionary *headers) {
    if (host.length == 0 || headers.count == 0) return;
    static dispatch_once_t once; dispatch_once(&once, ^{ g_hostHeaders = [NSMutableDictionary dictionary]; });
    NSMutableDictionary *dst = [g_hostHeaders[host] mutableCopy] ?: [NSMutableDictionary dictionary];
    for (NSString *k in headers) {
        id v = headers[k]; if (!v) continue;
        dst[k] = v;
    }
    g_hostHeaders[host] = dst;
}

// 取某域名的缓存头
static NSDictionary *AS_CachedHeadersForHost(NSString *host) {
    return host.length ? g_hostHeaders[host] : nil;
}

#pragma mark - Headers 构建/合并

static void AS_MergeHeadersFromRequest(NSMutableDictionary *dst, NSURLRequest *req) {
    if (!req) return;
    NSDictionary *h = req.allHTTPHeaderFields;
    if (h.count) [dst addEntriesFromDictionary:h];

    // 常见字段兜底
    if (!dst[@"Referer"] && req.URL) {
        NSString *ref = [NSString stringWithFormat:@"%@://%@", req.URL.scheme ?: @"https", req.URL.host ?: @""];
        if (ref.length > 0) dst[@"Referer"] = ref;
    }
    if (!dst[@"Origin"] && req.URL) {
        NSString *org = [NSString stringWithFormat:@"%@://%@", req.URL.scheme ?: @"https", req.URL.host ?: @""];
        if (org.length > 0) dst[@"Origin"] = org;
    }
    if (!dst[@"User-Agent"]) {
        NSString *ua = [NSString stringWithFormat:@"iOS/%@ (AliSniffer)", UIDevice.currentDevice.systemVersion];
        dst[@"User-Agent"] = ua;
    }
}

static NSString* AS_BuildHeadersText(NSDictionary *headers) {
    if (headers.count == 0) return @"";
    NSMutableString *s = [NSMutableString string];
    NSArray *keys = [[headers allKeys] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    for (NSString *k in keys) {
        [s appendFormat:@"%@: %@\n", k, headers[k]];
    }
    return [s copy];
}

#pragma mark - 统一上报（带/不带Headers）

static void ReportURL_WithHeaders(NSString *url, NSDictionary *headers, NSString *from);
static void ReportURL_Only(NSString *url, NSString *from);

// ✅ 对外入口：根据是否有 headers 分流
static void ReportURL(NSString *url, NSString *from) {
    if (url.length == 0) return;
    // 只有URL，走“推测Headers”
    ReportURL_Only(url, from);
}

static void ReportURL_WithHeaders(NSString *url, NSDictionary *headers, NSString *from) {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;
    if (IsNoiseURL(lower)) return;
    if (!IsPlayableURL(url)) return;

    NSMutableDictionary *hdr = [NSMutableDictionary dictionary];
    if (headers.count) [hdr addEntriesFromDictionary:headers];

    // 补全常见字段
    if (!hdr[@"Referer"]) {
        NSString *ref = [NSString stringWithFormat:@"%@://%@", [NSURL URLWithString:url].scheme ?: @"https", [NSURL URLWithString:url].host ?: @""];
        if (ref.length) hdr[@"Referer"] = ref;
    }
    if (!hdr[@"Origin"]) {
        NSString *org = [NSString stringWithFormat:@"%@://%@", [NSURL URLWithString:url].scheme ?: @"https", [NSURL URLWithString:url].host ?: @""];
        if (org.length) hdr[@"Origin"] = org;
    }
    if (!hdr[@"User-Agent"]) {
        hdr[@"User-Agent"] = [NSString stringWithFormat:@"iOS/%@ (AliSniffer)", UIDevice.currentDevice.systemVersion];
    }

    // 去重 Key：加入主要头避免抖动
    NSString *ua = [hdr[@"User-Agent"] ?: @"" description];
    NSString *rf = [hdr[@"Referer"]   ?: @"" description];
    NSString *ck = [hdr[@"Cookie"]    ?: @"" description];
    NSString *uniq = [NSString stringWithFormat:@"HDR|%@|%@|%@|%@", url, ua, rf, ck];
    if (SeenRecently(uniq, 10.0)) return;

    // 缓存到域名映射
    NSString *host = HostFromString(lower);
    AS_CacheHeadersForHost(host, hdr);

    NSString *hdrText = AS_BuildHeadersText(hdr);
    NSString *title = @"命中可疑播放 URL（含Headers）";
    if ([lower containsString:@"m3u8"]) title = @"抓到 M3U8（含Headers）";
    else if ([lower containsString:@".mp4"]) title = @"抓到 MP4（含Headers）";
    else if ([lower containsString:@".flv"] ||
             [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
             (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        title = @"抓到直播流 (FLV/RTMP)（含Headers）";
    }

    NSMutableString *msg = [NSMutableString stringWithFormat:@"URL:\n%@\n", url];
    if (hdrText.length) [msg appendFormat:@"\nHeaders:\n%@", hdrText];

    NSLog(@"[AliSniffer] %@(%@):\n%@", title, from, msg);
    ShowPopup(title, msg);
}

// 只有 URL 时：优先查找“域名缓存的Headers”，找到就合成“推测Headers”一起弹
static void ReportURL_Only(NSString *url, NSString *from) {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;
    if (IsNoiseURL(lower)) return;
    if (!IsPlayableURL(url)) return;

    NSString *host = HostFromString(lower);
    NSDictionary *cached = AS_CachedHeadersForHost(host);
    if (cached.count) {
        NSString *ua = [cached[@"User-Agent"] ?: @"" description];
        NSString *rf = [cached[@"Referer"]   ?: @"" description];
        NSString *ck = [cached[@"Cookie"]    ?: @"" description];
        NSString *uniq = [NSString stringWithFormat:@"CACHED|%@|%@|%@|%@", url, ua, rf, ck];
        if (SeenRecently(uniq, 10.0)) return;

        NSString *hdrText = AS_BuildHeadersText(cached);
        NSString *title = @"命中可疑播放 URL（推测Headers）";
        if ([lower containsString:@"m3u8"]) title = @"抓到 M3U8（推测Headers）";
        else if ([lower containsString:@".mp4"]) title = @"抓到 MP4（推测Headers）";
        else if ([lower containsString:@".flv"] ||
                 [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
                 (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
            title = @"抓到直播流 (FLV/RTMP)（推测Headers）";
        }

        NSMutableString *msg = [NSMutableString stringWithFormat:@"URL:\n%@\n", url];
        if (hdrText.length) [msg appendFormat:@"\nHeaders:\n%@", hdrText];

        NSLog(@"[AliSniffer] %@(%@):\n%@", title, from, msg);
        ShowPopup(title, msg);
        return;
    }

    // 否则保留“只有URL”的提示
    if (SeenRecently(url, 10.0)) return;
    NSString *title = @"命中可疑播放 URL";
    if ([lower containsString:@"m3u8"]) title = @"抓到 M3U8";
    else if ([lower containsString:@".mp4"]) title = @"抓到 MP4";
    else if ([lower containsString:@".flv"] ||
             [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
             (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        title = @"抓到直播流 (FLV/RTMP)";
    }
    NSLog(@"[AliSniffer] %@(%@): %@", title, from, url);
    ShowPopup(title, url);
}

#pragma mark - Swizzle & 辅助

static void Swz(Class c, SEL sel, IMP newImp, IMP *origStore) {
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    if (origStore) *origStore = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

static NSString *ExtractURLStringFromObj(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:NSString.class]) return obj;
    if ([obj isKindOfClass:NSURL.class])    return [(NSURL *)obj absoluteString];
    @try {
        id v = nil;
        if ([obj respondsToSelector:@selector(URL)])       v = [obj performSelector:@selector(URL)];
        if (!v && [obj respondsToSelector:@selector(url)]) v = [obj performSelector:@selector(url)];
        if ([v isKindOfClass:NSString.class]) return v;
        if ([v isKindOfClass:NSURL.class])    return [(NSURL *)v absoluteString];
    } @catch (...) {}
    return nil;
}

#pragma mark - ① AliPlayer / AliyunVodPlayer

static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    NSString *u = ExtractURLStringFromObj(source);
    if (u.length) ReportURL(u, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

static int (*orig_Ali_prepareURL)(id, SEL, NSString *);
static int swz_Ali_prepareURL(id self, SEL _cmd, NSString *url) {
    if (url.length) ReportURL(url, @"AliyunVodPlayer.prepareWithURL");
    return orig_Ali_prepareURL(self, _cmd, url);
}

static int (*orig_Ali_playURL)(id, SEL, NSString *);
static int swz_Ali_playURL(id self, SEL _cmd, NSString *url) {
    if (url.length) ReportURL(url, @"AliyunVodPlayer.play");
    return orig_Ali_playURL(self, _cmd, url);
}

#pragma mark - ② NSURLSessionTask.resume（带Headers + 缓存）

static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if ([self respondsToSelector:@selector(currentRequest)]) {
            NSURLRequest *req = [self performSelector:@selector(currentRequest)];
            if ([req isKindOfClass:NSURLRequest.class] && req.URL) {
                NSMutableDictionary *hdr = [NSMutableDictionary dictionary];
                AS_MergeHeadersFromRequest(hdr, req);
                AS_CacheHeadersForHost(req.URL.host.lowercaseString, hdr);
                ReportURL_WithHeaders(req.URL.absoluteString, hdr, @"NSURLSessionTask.resume");
            }
        }
    } @catch (...) {}
    orig_task_resume(self, _cmd);
}

#pragma mark - ③ NSURLProtocol（识别 MIME / #EXTM3U / video/x-flv）

@interface M3U8SniffProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@property(nonatomic,strong) NSMutableData *buf;
@property(nonatomic,assign) BOOL shouted;
@end

@implementation M3U8SniffProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"M3U8SniffHandled" inRequest:request]) return NO;
    NSString *sch = request.URL.scheme.lowercaseString;
    return [sch isEqualToString:@"http"] || [sch isEqualToString:@"https"];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"M3U8SniffHandled" inRequest:r];
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:r];
    self.buf = [NSMutableData data];
    [self.task resume];
}
- (void)stopLoading { [self.task cancel]; self.task = nil; self.buf = nil; }

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
 didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {

    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];

    if (!self.shouted) {
        NSString *mime = response.MIMEType.lowercaseString ?: @"";
        NSMutableDictionary *hdr = [NSMutableDictionary dictionary];
        AS_MergeHeadersFromRequest(hdr, dataTask.currentRequest);
        AS_CacheHeadersForHost(dataTask.currentRequest.URL.host.lowercaseString, hdr);

        // m3u8 MIME
        if ([mime containsString:@"mpegurl"]) {
            ReportURL_WithHeaders(dataTask.currentRequest.URL.absoluteString, hdr, @"NSURLProtocol(MIME-M3U8)");
            self.shouted = YES;
        }
        // FLV MIME
        else if ([mime containsString:@"x-flv"] || [mime containsString:@"/flv"]) {
            ReportURL_WithHeaders(dataTask.currentRequest.URL.absoluteString, hdr, @"NSURLProtocol(MIME-FLV)");
            self.shouted = YES;
        }
    }

    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
    if (!self.shouted && self.buf.length < 16*1024) {
        [self.buf appendData:data];
        NSString *head = [[NSString alloc] initWithData:self.buf encoding:NSUTF8StringEncoding];
        if (head && [head containsString:@"#EXTM3U"]) {
            NSMutableDictionary *hdr = [NSMutableDictionary dictionary];
            AS_MergeHeadersFromRequest(hdr, dataTask.currentRequest);
            AS_CacheHeadersForHost(dataTask.currentRequest.URL.host.lowercaseString, hdr);
            ReportURL_WithHeaders(dataTask.currentRequest.URL.absoluteString, hdr, @"NSURLProtocol(#EXTM3U)");
            self.shouted = YES;
        }
    }
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

// 注入三种配置（default/ephemeral/background）
static NSURLSessionConfiguration* (*orig_defCfg)(id, SEL);
static NSURLSessionConfiguration* swz_defCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_defCfg(self, _cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:M3U8SniffProtocol.class]) [arr insertObject:M3U8SniffProtocol.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}
static NSURLSessionConfiguration* (*orig_ephCfg)(id, SEL);
static NSURLSessionConfiguration* swz_ephCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_ephCfg(self, _cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:M3U8SniffProtocol.class]) [arr insertObject:M3U8SniffProtocol.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}
static NSURLSessionConfiguration* (*orig_bgCfg)(id, SEL, NSString *);
static NSURLSessionConfiguration* swz_bgCfg(id self, SEL _cmd, NSString *identifier) {
    NSURLSessionConfiguration *cfg = orig_bgCfg(self, _cmd, identifier);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:M3U8SniffProtocol.class]) [arr insertObject:M3U8SniffProtocol.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}

#pragma mark - ④ CFReadStream Hook（只拿到URL时也会走“推测Headers”）

typedef CFURLRef (*PFN_CFHTTPMessageCopyRequestURL)(CFHTTPMessageRef);
static PFN_CFHTTPMessageCopyRequestURL p_CFHTTPMessageCopyRequestURL = NULL;

typedef CFReadStreamRef (*PFN_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static PFN_CFReadStreamCreateForHTTPRequest orig_CFReadStreamCreateForHTTPRequest = NULL;

static CFReadStreamRef hook_CFReadStreamCreateForHTTPRequest(CFAllocatorRef a, CFHTTPMessageRef req) {
    if (req && p_CFHTTPMessageCopyRequestURL) {
        CFURLRef u = p_CFHTTPMessageCopyRequestURL(req);
        if (u) {
            NSString *url = [(__bridge NSURL *)u absoluteString];
            if (url.length) {
                // 只有URL，后续用“域名缓存”补齐
                ReportURL_Only(url, @"CFReadStreamCreateForHTTPRequest");
            }
        }
    }
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(a, req) : NULL;
}

#pragma mark - ⑤ AVPlayer / AVURLAsset（原生播放器）

static id (*orig_AVPI_initWithURL)(id, SEL, NSURL *);
static id swz_AVPI_initWithURL(id self, SEL _cmd, NSURL *url) {
    if (url) ReportURL(url.absoluteString, @"AVPlayerItem.initWithURL");
    return orig_AVPI_initWithURL(self, _cmd, url);
}

static id (*orig_AVPI_playerItemWithURL)(id, SEL, NSURL *);
static id swz_AVPI_playerItemWithURL(id self, SEL _cmd, NSURL *url) {
    if (url) ReportURL(url.absoluteString, @"AVPlayerItem.playerItemWithURL");
    return orig_AVPI_playerItemWithURL(self, _cmd, url);
}

static id (*orig_AVURLA_initWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_initWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) {
    if (url) ReportURL(url.absoluteString, @"AVURLAsset.initWithURL");
    return orig_AVURLA_initWithURL(self, _cmd, url, opt);
}

static id (*orig_AVURLA_assetWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_assetWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) {
    if (url) ReportURL(url.absoluteString, @"AVURLAsset.assetWithURL");
    return orig_AVURLA_assetWithURL(self, _cmd, url, opt);
}

#pragma mark - ⑥ WKWebView 注入 JS（抓 H5，含 flv/rtmp）

@interface AliWKHandler : NSObject<WKScriptMessageHandler>
@end
@implementation AliWKHandler
- (void)userContentController:(WKUserContentController *)uc didReceiveScriptMessage:(WKScriptMessage *)m {
    if ([m.name isEqualToString:@"AliSniffer"]) {
        NSString *url = [m.body isKindOfClass:NSString.class] ? (NSString *)m.body : @"";
        if (url.length) ReportURL(url, @"WKWebView(JS)");
    }
}
@end

static char kAliWKHandlerKey;
static char kAliWKUserScriptKey;

static id (*orig_WK_init)(id, SEL, CGRect, WKWebViewConfiguration *);
static id swz_WK_init(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    if (cfg) {
        AliWKHandler *handler = [AliWKHandler new];
        objc_setAssociatedObject(cfg, &kAliWKHandlerKey, handler, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [cfg.userContentController addScriptMessageHandler:handler name:@"AliSniffer"];

        NSString *js =
        @"(function(){"
          "function report(u){try{"
            "if(u && /(m3u8|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)/i.test(u)){"
              "window.webkit.messageHandlers.AliSniffer.postMessage(u);"
            "}"
          "}catch(e){}}"
          // fetch
          "var _f=window.fetch; if(_f){window.fetch=function(){var u=arguments[0]; if(typeof u==='string'){report(u);} "
          "return _f.apply(this,arguments).then(function(res){try{var u=res&&res.url; if(u)report(u);}catch(e){} return res;});};}"
          // XHR
          "var X=window.XMLHttpRequest; if(X){var op=X.prototype.open, sd=X.prototype.send;"
          "X.prototype.open=function(m,u){try{this.__u=u;report(u);}catch(e){} return op.apply(this,arguments)};"
          "X.prototype.send=function(){try{report(this.__u);}catch(e){} return sd.apply(this,arguments)};}"
          // <video>.src
          "if(window.HTMLMediaElement){var ds=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');"
          "if(ds&&ds.set){Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{report(v);}catch(e){} return ds.set.call(this,v);},get:ds.get});}}"
        "})();";

        WKUserScript *script = [[WKUserScript alloc] initWithSource:js
                                                     injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                                  forMainFrameOnly:NO];
        [cfg.userContentController addUserScript:script];
        objc_setAssociatedObject(cfg, &kAliWKUserScriptKey, script, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return orig_WK_init(self, _cmd, frame, cfg);
}

#pragma mark - ⑦ libcurl：CURLOPT_URL

typedef int CURLcode;
static CURLcode (*orig_curl_easy_setopt)(void *curl, int option, ...);

static CURLcode hook_curl_easy_setopt(void *curl, int option, ...) {
    va_list ap; va_start(ap, option);

    if (option == 10002 /* CURLOPT_URL */) {
        const char *c_url = va_arg(ap, const char *);
        if (c_url) {
            NSString *url = [NSString stringWithUTF8String:c_url];
            if (url.length) ReportURL(url, @"curl_easy_setopt(CURLOPT_URL)");
        }
        va_end(ap);
        va_start(ap, option);
        (void)va_arg(ap, const char *);
    }

    CURLcode ret = 0;
    if (orig_curl_easy_setopt) {
        const void *p = va_arg(ap, const void *);
        ret = orig_curl_easy_setopt(curl, option, p);
    }
    va_end(ap);
    return ret;
}

static void InstallCurlHook(void) {
    struct rebinding rbs[] = {
        {"curl_easy_setopt", (void *)hook_curl_easy_setopt, (void **)&orig_curl_easy_setopt}
    };
    rebind_symbols(rbs, sizeof(rbs)/sizeof(rbs[0]));
    NSLog(@"[AliSniffer] fishhook curl_easy_setopt");
}

#pragma mark - 安装所有 Hook

__attribute__((constructor))
static void _ali_sniffer_init(void) {
    @autoreleasepool {
        // AliPlayer / AliyunVodPlayer
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        if (AliPlayer && [AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
            Swz(AliPlayer, @selector(setUrlSource:), (IMP)swz_Ali_setUrlSource, (IMP *)&orig_Ali_setUrlSource);
        }
        Class AliVod = NSClassFromString(@"AliyunVodPlayer");
        if (AliVod && [AliVod instancesRespondToSelector:@selector(prepareWithURL:)]) {
            Swz(AliVod, @selector(prepareWithURL:), (IMP)swz_Ali_prepareURL, (IMP *)&orig_Ali_prepareURL);
        }
        if (AliVod && [AliVod instancesRespondToSelector:@selector(play:)]) {
            Swz(AliVod, @selector(play:), (IMP)swz_Ali_playURL, (IMP *)&orig_Ali_playURL);
        }

        // NSURLSessionTask.resume
        Class Task = NSClassFromString(@"NSURLSessionTask");
        if (Task && class_getInstanceMethod(Task, @selector(resume))) {
            Swz(Task, @selector(resume), (IMP)swz_task_resume, (IMP *)&orig_task_resume);
        }

        // NSURLSessionConfiguration 注入（default / ephemeral / background）
        Class Cfg = NSURLSessionConfiguration.class;
        if ([Cfg respondsToSelector:@selector(defaultSessionConfiguration)]) {
            Method m = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
            orig_defCfg = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_defCfg);
        }
        if ([Cfg respondsToSelector:@selector(ephemeralSessionConfiguration)]) {
            Method m = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
            orig_ephCfg = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_ephCfg);
        }
        if ([Cfg respondsToSelector:@selector(backgroundSessionConfigurationWithIdentifier:)]) {
            Method m = class_getClassMethod(Cfg, @selector(backgroundSessionConfigurationWithIdentifier:));
            orig_bgCfg = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_bgCfg);
        }

        // CFReadStream hook（运行时解析符号）
        void *hCF = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_NOW);
        if (hCF) {
            p_CFHTTPMessageCopyRequestURL =
            (PFN_CFHTTPMessageCopyRequestURL)dlsym(hCF, "CFHTTPMessageCopyRequestURL");
        }
        struct rebinding r1[] = {
            {"CFReadStreamCreateForHTTPRequest", (void *)hook_CFReadStreamCreateForHTTPRequest, (void **)&orig_CFReadStreamCreateForHTTPRequest}
        };
        rebind_symbols(r1, sizeof(r1)/sizeof(r1[0]));

        // AVPlayer / AVURLAsset
        Class AVPI = NSClassFromString(@"AVPlayerItem");
        if (AVPI) {
            Method m1 = class_getInstanceMethod(AVPI, @selector(initWithURL:));
            if (m1) { orig_AVPI_initWithURL = (void *)method_getImplementation(m1);
                      method_setImplementation(m1, (IMP)swz_AVPI_initWithURL); }
            Method m2 = class_getClassMethod(AVPI, @selector(playerItemWithURL:));
            if (m2) { orig_AVPI_playerItemWithURL = (void *)method_getImplementation(m2);
                      method_setImplementation(m2, (IMP)swz_AVPI_playerItemWithURL); }
        }
        Class AVURLA = NSClassFromString(@"AVURLAsset");
        if (AVURLA) {
            Method m3 = class_getInstanceMethod(AVURLA, @selector(initWithURL:options:));
            if (m3) { orig_AVURLA_initWithURL = (void *)method_getImplementation(m3);
                      method_setImplementation(m3, (IMP)swz_AVURLA_initWithURL); }
            Method m4 = class_getClassMethod(AVURLA, @selector(URLAssetWithURL:options:));
            if (m4) { orig_AVURLA_assetWithURL = (void *)method_getImplementation(m4);
                      method_setImplementation(m4, (IMP)swz_AVURLA_assetWithURL); }
        }

        // WKWebView 注入
        Class WK = NSClassFromString(@"WKWebView");
        if (WK) {
            Method m = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
            if (m) { orig_WK_init = (void *)method_getImplementation(m);
                     method_setImplementation(m, (IMP)swz_WK_init); }
        }

        // libcurl hook
        InstallCurlHook();

        ShowPopup(@"AliSniffer 已加载", @"已支持 m3u8/mp4/FLV/RTMP + 自动补齐Headers + Background NSURLSession");
        NSLog(@"[AliSniffer] ready.");
    }
}
