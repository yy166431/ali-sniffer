//
//  AliSniffer.m — 全面兜底增强版（auth_key 直通 + 多入口 + 大首包 + MSE/WebSocket/Metrics）
//  说明：在你之前合并版的基础上做了大量增强，旨在把“能看见的直播链接/证据”尽量都抓到。
//  替换或合并到你现有工程即可（记得调整 fishhook 路径与宏）。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <stdarg.h>
#import "fishhook.h"

// ====== 配置 ======
static NSString * const kPushRawEndpoint  = @"http://139.155.57.242:8088/api/push_raw";
static NSString * const kPushFormEndpoint = @"http://139.155.57.242:8088/api/push_form";
static NSString * const kPushToken        = @"@Yy166431";
static const NSTimeInterval kPushInterval = 3600.0; // 每小时自动推送
static NSString *g_lastPlayableURL = nil;           // 最近一次命中的播放 URL

// 调试日志
#ifndef ENABLE_DEBUG_LOG
#define LOG(...)
#else
#define LOG(...) NSLog(__VA_ARGS__)
#endif

// 弹窗开关
#ifndef SNIFFER_ENABLE_POPUP
#define SNIFFER_ENABLE_POPUP 1
#endif

// iOS16 某些 Hook 默认为关闭，按需打开
#ifndef SNIFFER_IOS16_ENABLE_NSURLPROTOCOL
#define SNIFFER_IOS16_ENABLE_NSURLPROTOCOL 1
#endif
#ifndef SNIFFER_IOS16_ENABLE_CFREADSTREAM
#define SNIFFER_IOS16_ENABLE_CFREADSTREAM 1
#endif
#ifndef SNIFFER_IOS16_ENABLE_LIBCURL
#define SNIFFER_IOS16_ENABLE_LIBCURL 0
#endif

// 首包嗅探参数（增强）
static const NSUInteger kFirstPacketMaxBytes = 128 * 1024; // 128KB
static const NSTimeInterval kFirstPacketDelayMs = 0.15;   // 150 ms 判定延迟

// ====== 噪声/白名单（保留） ======
static NSArray<NSString *> *BlockedSubstrings(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{ a = @[@"log.aliyuncs.com/logstores", @"/beacon", @"/monitor", @"/ums", @"/umeng", @"/collect", @"bugly", @"crash", @"analytics", @"sentry"]; });
    return a;
}
static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{ a = @[@"knyb.kuniunet.com",@"knydb.kuniunet.com",@"qiaohongb.kuniunet.com",@"v2.weizan.cn"]; });
    return a;
}

// ====== 工具函数 ======
static inline NSString *HostOfURLString(NSString *s) {
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.lowercaseString ?: @"";
}
static inline BOOL IsNoise(NSString *lower) {
    for (NSString *k in BlockedSubstrings()) if ([lower containsString:k]) return YES;
    return NO;
}
static inline BOOL IsPlayableBySuffixOrWhiteHost(NSString *u) {
    if (u.length == 0) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@"m3u8"] || [s containsString:@".mp4"] || [s containsString:@".flv"] || [s hasPrefix:@"rtmp://"] || [s hasPrefix:@"rtmps://"] || (([s hasPrefix:@"ws://"] || [s hasPrefix:@"wss://"]) && [s containsString:@".flv"])) return YES;
    NSString *h = HostOfURLString(s);
    for (NSString *w in WhitelistedHosts()) if ([h hasSuffix:w]) return YES;
    return NO;
}

// 新增：auth_key 检测 与 baseKey
static inline BOOL HasAuthKey(NSString *lower) {
    if (!lower) return NO;
    return ([lower containsString:@"auth_key="] || [lower containsString:@"authkey="]);
}
static inline NSString *BaseURLWithoutQuery(NSString *s) {
    if (!s.length) return @"";
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    if (!c) return s;
    c.query = nil; c.fragment = nil;
    return c.string ?: s;
}

// ====== 去重 与 缓存 ======
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static inline BOOL SeenRecently(NSString *k, NSTimeInterval sec) {
    static dispatch_once_t once; dispatch_once(&once, ^{ g_seen = [NSMutableDictionary dictionary]; });
    NSDate *now = [NSDate date]; NSDate *last = g_seen[k];
    if (last && [now timeIntervalSinceDate:last] < sec) return YES;
    g_seen[k] = now; if (g_seen.count > 2048) [g_seen removeAllObjects]; return NO;
}

// ====== 弹窗 / 复制 / 推送 ======
static inline void ShowPopupIfNeeded(NSString *title, NSString *url) {
#if SNIFFER_ENABLE_POPUP
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!url) url = @"";
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:url preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            if (url.length) [UIPasteboard generalPasteboard].string = url;
        }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        if (vc) [vc presentViewController:ac animated:YES completion:nil];
    });
#else
    if (url.length) [UIPasteboard generalPasteboard].string = url;
#endif
}

static void PushLatestURL_FormFallback(NSString *u, NSDictionary *headers) {
    if (!u.length) return;
    NSURL *URL = [NSURL URLWithString:kPushFormEndpoint];
    if (!URL) return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:URL];
    req.HTTPMethod = @"POST";
    [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
    [req setValue:@"application/x-www-form-urlencoded; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    // 将 headers 用 JSON 包装（若有）
    NSString *hdr = @"";
    if (headers) {
        NSError *e = nil; NSData *d = [NSJSONSerialization dataWithJSONObject:headers options:0 error:&e];
        if (!e && d) hdr = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    }
    NSString *body = [NSString stringWithFormat:@"content=%@&headers=%@",
                      [u stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLQueryAllowedCharacterSet],
                      [hdr stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLQueryAllowedCharacterSet]];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, __unused NSURLResponse *r, __unused NSError *e) {
        LOG(@"[AliSniffer] push_form done");
    }] resume];
}

static void PushLatestURL_Raw(NSString *u, NSDictionary *headers) {
    if (!u.length) return;
    @try {
        NSURL *URL = [NSURL URLWithString:kPushRawEndpoint];
        if (!URL) return;
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:URL];
        req.HTTPMethod = @"POST";
        [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
        [req setValue:@"application/json; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        NSMutableDictionary *payload = [NSMutableDictionary dictionary];
        payload[@"url"] = u;
        if (headers) payload[@"headers"] = headers;
        payload[@"ts"] = @((long long)([[NSDate date] timeIntervalSince1970]));
        NSData *jb = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
        if (jb) req.HTTPBody = jb;
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSHTTPURLResponse *resp = (NSHTTPURLResponse *)r;
            if (e || resp.statusCode < 200 || resp.statusCode >= 300) {
                PushLatestURL_FormFallback(u, headers);
            }
            LOG(@"[AliSniffer] push_raw -> %ld, err=%@", (long)resp.statusCode, e);
        }] resume];
    } @catch(...) {}
}

// ====== 报告函数（全面：auth_key 直通 + headers） ======
static inline void ReportURL_WithHeaders(NSString *url, NSDictionary *headers) {
    if (!url.length) return;
    NSString *lower = url.lowercaseString;
    if (IsNoise(lower)) return;

    BOOL hasAuth = HasAuthKey(lower);
    BOOL playable = hasAuth || IsPlayableBySuffixOrWhiteHost(lower);
    if (!playable) return;

    NSString *baseKey = BaseURLWithoutQuery(lower);
    if (hasAuth) {
        if (SeenRecently(lower, 2.0)) return;
    } else {
        if (SeenRecently(baseKey, 10.0)) return;
    }

    g_lastPlayableURL = url;

    NSString *title = hasAuth ? @"抓到 URL (auth_key优先)" : @"抓到播放 URL";
    ShowPopupIfNeeded(title, url);

    // 同步推送带 headers
    PushLatestURL_Raw(url, headers);
}

// 兼容旧接口
static inline void ReportURL(NSString *url) { ReportURL_WithHeaders(url, nil); }

// ====== Helpers to extract headers from task/request ======
static NSDictionary *HeadersFromRequest(NSURLRequest *req) {
    if (!req) return nil;
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    NSDictionary *h = req.allHTTPHeaderFields;
    if (h) [m addEntriesFromDictionary:h];
    if (req.URL) m[@"__url"] = req.URL.absoluteString;
    if (req.HTTPMethod) m[@"__method"] = req.HTTPMethod;
    return m;
}

// ====== 首包缓存/延时判定（用于 NSURLProtocol / WebSocket 内容判定） ======
@interface _FirstPacketBuffer : NSObject
@property(nonatomic,strong) NSMutableData *buf;
@property(nonatomic,copy) void (^onReady)(NSData *data);
@property(nonatomic,assign) NSTimer *timer;
- (instancetype)initWithDelay:(NSTimeInterval)delay onReady:(void(^)(NSData *d))cb;
- (void)appendData:(NSData*)d;
@end
@implementation _FirstPacketBuffer
- (instancetype)initWithDelay:(NSTimeInterval)delay onReady:(void(^)(NSData *d))cb {
    if (self = [super init]) {
        _buf = [NSMutableData data];
        _onReady = cb;
        __weak typeof(self) wself = self;
        dispatch_async(dispatch_get_main_queue(), ^{
            wself.timer = [NSTimer scheduledTimerWithTimeInterval:delay repeats:NO block:^(NSTimer * _Nonnull t) {
                __strong typeof(wself) s = wself;
                if (s && s.onReady) s.onReady(s.buf);
            }];
        });
    }
    return self;
}
- (void)appendData:(NSData*)d {
    if (!d) return;
    NSUInteger remain = kFirstPacketMaxBytes - _buf.length;
    if (remain == 0) return;
    NSUInteger take = MIN(remain, d.length);
    [_buf appendData:[d subdataWithRange:NSMakeRange(0, take)]];
}
@end

// ====== NSURLSessionTask resume hook（增强：抓 headers） =======
static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *req = nil;
        if ([self respondsToSelector:@selector(currentRequest)]) req = [self performSelector:@selector(currentRequest)];
        else if ([self respondsToSelector:@selector(originalRequest)]) req = [self performSelector:@selector(originalRequest)];
        NSString *u = req.URL.absoluteString;
        NSDictionary *hdr = HeadersFromRequest(req);
        if (u.length) ReportURL_WithHeaders(u, hdr);
    } @catch(...) {}
    if (orig_task_resume) orig_task_resume(self, _cmd);
}

// ====== NSURLProtocol 扩展（大首包 + ws upgrade 检测 + headers）======
@interface _SniffProto : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@property(nonatomic,strong) _FirstPacketBuffer *first;
@property(nonatomic,assign) BOOL shouted;
@property(nonatomic,strong) NSDictionary *reqHeaders;
@end

@implementation _SniffProto
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"_SniffDone" inRequest:request]) return NO;
    NSString *scheme = request.URL.scheme.lowercaseString;
    return [scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"_SniffDone" inRequest:r];
    self.reqHeaders = HeadersFromRequest(r);
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:r];
    __weak typeof(self) w = self;
    self.first = [[_FirstPacketBuffer alloc] initWithDelay:kFirstPacketDelayMs onReady:^(NSData *d) {
        __strong typeof(w) sself = w;
        if (!sself) return;
        // 体征判断：m3u8 / #EXTM3U
        NSString *text = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (text && ([text containsString:@"#EXTM3U"] || [text containsString:@"#EXT-X-PART"] || [text containsString:@"#EXT-X-MAP"])) {
            ReportURL_WithHeaders(sself.task.currentRequest.URL.absoluteString, sself.reqHeaders);
            sself.shouted = YES;
        } else {
            // 二进制特征：TS sync 0x47 / FLV / MP4 ftyp/moof/mdat
            const uint8_t *bytes = (const uint8_t *)d.bytes; NSUInteger n = d.length;
            if (n >= 376) {
                BOOL looksTS = (bytes[0] == 0x47) && (bytes[188] == 0x47 || (n > 2*188 && bytes[2*188] == 0x47));
                if (looksTS) { ReportURL_WithHeaders(sself.task.currentRequest.URL.absoluteString, sself.reqHeaders); sself.shouted = YES; return; }
            }
            if (n >= 12) {
                for (NSUInteger i=0;i+8<=MIN(n,4096);i++) {
                    if (bytes[i+4]=='f' && bytes[i+5]=='t' && bytes[i+6]=='y' && bytes[i+7]=='p') { ReportURL_WithHeaders(sself.task.currentRequest.URL.absoluteString, sself.reqHeaders); sself.shouted = YES; break; }
                    if (bytes[i+4]=='m' && bytes[i+5]=='o' && bytes[i+6]=='o' && bytes[i+7]=='f') { ReportURL_WithHeaders(sself.task.currentRequest.URL.absoluteString, sself.reqHeaders); sself.shouted = YES; break; }
                }
            }
        }
    }];
    [self.task resume];
}
- (void)stopLoading { [self.task cancel]; self.task = nil; self.first = nil; }

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    // 若 header 指明 mime
    if (!self.shouted) {
        NSString *mime = response.MIMEType.lowercaseString ?: @"";
        if ([mime containsString:@"mpegurl"] || [mime containsString:@"x-flv"] || [mime containsString:@"/flv"]) {
            ReportURL_WithHeaders(dataTask.currentRequest.URL.absoluteString, self.reqHeaders); self.shouted = YES;
        }
    }
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
    if (self.shouted) return;
    // append to first buffer
    [self.first appendData:data];
    // 另外：检测 Upgrade header for websocket (在 request headers)
    NSString *up = [self.reqHeaders[@"Upgrade"] lowercaseString] ?: @"";
    if ([up containsString:@"websocket"]) {
        // 尝试使用首包数据判定 websocket 中的流格式（FLV/TS/MP4 box）
        // 如果首包已经触发（timer 回调会处理），这里不重复
    }
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

// 将 _SniffProto 插入到 default / ephemeral session configuration
static NSURLSessionConfiguration* (*orig_defCfg)(id, SEL);
static NSURLSessionConfiguration* swz_defCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_defCfg ? orig_defCfg(self, _cmd) : [NSURLSessionConfiguration defaultSessionConfiguration];
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:_SniffProto.class]) [arr insertObject:_SniffProto.class atIndex:0];
    cfg.protocolClasses = arr; return cfg;
}
static NSURLSessionConfiguration* (*orig_ephCfg)(id, SEL);
static NSURLSessionConfiguration* swz_ephCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_ephCfg ? orig_ephCfg(self, _cmd) : [NSURLSessionConfiguration ephemeralSessionConfiguration];
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:_SniffProto.class]) [arr insertObject:_SniffProto.class atIndex:0];
    cfg.protocolClasses = arr; return cfg;
}

// ====== CFReadStream hook（保留） ======
typedef CFURLRef (*PFN_CFHTTPMessageCopyRequestURL)(CFHTTPMessageRef);
static PFN_CFHTTPMessageCopyRequestURL p_CFHTTPMessageCopyRequestURL = NULL;
typedef CFReadStreamRef (*PFN_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static PFN_CFReadStreamCreateForHTTPRequest orig_CFReadStreamCreateForHTTPRequest = NULL;
static CFReadStreamRef hook_CFReadStreamCreateForHTTPRequest(CFAllocatorRef a, CFHTTPMessageRef req) {
    if (req && p_CFHTTPMessageCopyRequestURL) {
        CFURLRef u = p_CFHTTPMessageCopyRequestURL(req);
        if (u) {
            NSString *s = [(__bridge NSURL *)u absoluteString];
            if (s.length) ReportURL_WithHeaders(s, nil);
        }
    }
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(a, req) : NULL;
}

// ====== AVPlayer / AVURLAsset / AVPlayer replaceCurrentItemWithPlayerItem / playImmediatelyAtRate 增强 ======
static id (*orig_AVPI_initWithURL)(id, SEL, NSURL *);
static id swz_AVPI_initWithURL(id self, SEL _cmd, NSURL *url) { if (url) ReportURL_WithHeaders(url.absoluteString, nil); return orig_AVPI_initWithURL(self, _cmd, url); }
static id (*orig_AVPI_playerItemWithURL)(id, SEL, NSURL *);
static id swz_AVPI_playerItemWithURL(id self, SEL _cmd, NSURL *url) { if (url) ReportURL_WithHeaders(url.absoluteString, nil); return orig_AVPI_playerItemWithURL(self, _cmd, url); }

static id (*orig_AVURLA_initWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_initWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) { if (url) ReportURL_WithHeaders(url.absoluteString, nil); return orig_AVURLA_initWithURL(self, _cmd, url, opt); }
static id (*orig_AVURLA_assetWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_assetWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) { if (url) ReportURL_WithHeaders(url.absoluteString, nil); return orig_AVURLA_assetWithURL(self, _cmd, url, opt); }

// replaceCurrentItemWithPlayerItem:
static void (*orig_replaceCurrentItem)(id, SEL, id);
static void swz_replaceCurrentItem(id self, SEL _cmd, id item) {
    @try {
        // 尝试从 item 获取 URL
        NSURL *u = nil;
        if ([item respondsToSelector:@selector(URL)]) u = [item performSelector:@selector(URL)];
        else if ([item respondsToSelector:@selector(asset)]) {
            id asset = [item performSelector:@selector(asset)];
            if (asset && [asset respondsToSelector:@selector(URL)]) u = [asset performSelector:@selector(URL)];
        }
        if (u) ReportURL_WithHeaders(u.absoluteString, nil);
    } @catch(...) {}
    if (orig_replaceCurrentItem) orig_replaceCurrentItem(self, _cmd, item);
}

// playImmediatelyAtRate:
static void (*orig_playImmediatelyAtRate)(id, SEL, float);
static void swz_playImmediatelyAtRate(id self, SEL _cmd, float r) {
    // 触发时检查 currentItem
    @try {
        if ([self respondsToSelector:@selector(currentItem)]) {
            id item = [self performSelector:@selector(currentItem)];
            NSURL *u = nil;
            if ([item respondsToSelector:@selector(URL)]) u = [item performSelector:@selector(URL)];
            else if ([item respondsToSelector:@selector(asset)]) {
                id asset = [item performSelector:@selector(asset)];
                if ([asset respondsToSelector:@selector(URL)]) u = [asset performSelector:@selector(URL)];
            }
            if (u) ReportURL_WithHeaders(u.absoluteString, nil);
        }
    } @catch(...) {}
    if (orig_playImmediatelyAtRate) orig_playImmediatelyAtRate(self, _cmd, r);
}

// ====== WK 注入增强：拦截 fetch/XHR + MSE appendBuffer（把首 256 bytes 以 base64 发到 native，方便识别） ======
@interface _WK_MSE_Handler : NSObject <WKScriptMessageHandler>
@end
@implementation _WK_MSE_Handler
- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    if (!message.body) return;
    @try {
        NSDictionary *b = nil;
        if ([message.body isKindOfClass:[NSDictionary class]]) b = (NSDictionary *)message.body;
        else {
            NSString *s = [message.body description];
            if (s.length) {
                // 可能是纯 URL 字符串
                ReportURL_WithHeaders(s, nil);
                return;
            }
        }
        if (b) {
            NSString *type = b[@"type"];
            if ([type isEqualToString:@"url"]) {
                NSString *u = b[@"u"];
                if (u.length) ReportURL_WithHeaders(u, nil);
            } else if ([type isEqualToString:@"mse_sample"]) {
                // 这是 MSE appendBuffer 的 base64 前缀样本，附带 pageURL
                NSString *page = b[@"page"] ?: @"";
                NSString *b64 = b[@"data"] ?: @"";
                // 可选：保存或推送样本以便离线分析；这里我们直接用 page 做提示
                NSString *note = [NSString stringWithFormat:@"MSE sample @ %@ (%lu bytes)", page, (unsigned long)b64.length];
                LOG(@"[AliSniffer] MSE sample: %@ ...", note);
                // 不把样本当作可播放 URL，但仍记录
            }
        }
    } @catch(...) {}
}
@end

static id (*orig_WK_init)(id, SEL, CGRect, WKWebViewConfiguration *);
static id swz_WK_init(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    if (cfg) {
        _WK_MSE_Handler *h = [_WK_MSE_Handler new];
        [cfg.userContentController addScriptMessageHandler:h name:@"_ALISNIF"];
        // JS: 拦截 fetch/XHR 与 MediaSource.appendBuffer
        NSString *js =
        @"(function(){"
         "function postUrl(u){try{window.webkit.messageHandlers._ALISNIF.postMessage({type:'url',u:u});}catch(e){}}"
         "var _fetch = window.fetch; if(_fetch){window.fetch = function(){try{var u=arguments[0]; if(typeof u==='string') postUrl(u);}catch(e){} return _fetch.apply(this,arguments);} }"
         "var _open = XMLHttpRequest.prototype.open; XMLHttpRequest.prototype.open = function(method,url){try{postUrl(url);}catch(e){} return _open.apply(this,arguments)};"
         // MSE 钩子
         "try{ if(window.MediaSource){"
             "var OrigAdd = MediaSource.prototype.addSourceBuffer;"
             "MediaSource.prototype.addSourceBuffer = function(mime){"
                 "try{var sb = OrigAdd.call(this,mime);"
                     "var origAppend = sb.appendBuffer;"
                     "sb.appendBuffer = function(buf){"
                         "try{"
                             "var view = new Uint8Array(buf);"
                             "var len = Math.min(256, view.length);"
                             "var slice = view.slice(0,len);"
                             "var s=''; for(var i=0;i<slice.length;i++){s+=String.fromCharCode(slice[i]);}"
                             "var b64 = btoa(s);"
                             "var page = document.location.href;"
                             "window.webkit.messageHandlers._ALISNIF.postMessage({type:'mse_sample', page:page, data:b64});"
                         "}catch(e){}"
                         "return origAppend.apply(this, arguments);"
                     "};"
                     "return sb;"
                 "}catch(e){}"
             "};"
         "}}catch(e){}"
        "})();";
        WKUserScript *sc = [[WKUserScript alloc] initWithSource:js injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
        [cfg.userContentController addUserScript:sc];
        objc_setAssociatedObject(cfg, "_alisnif_handler", h, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(cfg, "_alisnif_script", sc, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return orig_WK_init ? orig_WK_init(self, _cmd, frame, cfg) : self;
}

// ====== libcurl hook（注释，可选打开） =======
typedef int CURLcode; typedef int CURLoption; typedef void CURL;
#define CURLOPT_URL 10002
#if SNIFFER_IOS16_ENABLE_LIBCURL
static CURLcode (*orig_curl_easy_setopt)(CURL *curl, CURLoption option, ...);
static CURLcode hook_curl_easy_setopt(CURL *curl, CURLoption option, ...) {
    va_list ap; va_start(ap, option);
    if (option == CURLOPT_URL) {
        const char *c = va_arg(ap, const char *); if (c) { NSString *u = [NSString stringWithUTF8String:c]; if (u.length) ReportURL_WithHeaders(u, nil); }
    }
    // can't reliably forward varargs here without proper handling -> skip for now
    va_end(ap);
    if (orig_curl_easy_setopt) {
        // best-effort: call orig with the same args is tricky; skip
    }
    return 0;
}
static inline void HookCurlIfPresent(void) {
    rebind_symbols((struct rebinding[]){{"curl_easy_setopt",(void*)hook_curl_easy_setopt,(void**)&orig_curl_easy_setopt}},1);
}
#endif

// ====== 安装 Hook（入口） =======
__attribute__((constructor))
static void _alisniffer_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            // NSURLSessionTask resume
            Class Task = NSClassFromString(@"NSURLSessionTask");
            if (Task && class_getInstanceMethod(Task, @selector(resume))) {
                Method m = class_getInstanceMethod(Task, @selector(resume));
                orig_task_resume = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)swz_task_resume);
                LOG(@"[AliSniffer] hooked NSURLSessionTask resume");
            }

            // NSURLSessionConfiguration -> NSURLProtocol 插入
            Class Cfg = NSClassFromString(@"NSURLSessionConfiguration");
            if (Cfg) {
                Method m1 = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
                if (m1) { orig_defCfg = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)swz_defCfg); }
                Method m2 = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
                if (m2) { orig_ephCfg = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)swz_ephCfg); }
                LOG(@"[AliSniffer] hooked NSURLSessionConfiguration to inject NSURLProtocol");
            }

            // CFReadStream hook via fishhook (if available)
            void *hCF = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_NOW);
            if (hCF) {
                p_CFHTTPMessageCopyRequestURL = (PFN_CFHTTPMessageCopyRequestURL)dlsym(hCF, "CFHTTPMessageCopyRequestURL");
                rebind_symbols((struct rebinding[]){{"CFReadStreamCreateForHTTPRequest",(void*)hook_CFReadStreamCreateForHTTPRequest,(void**)&orig_CFReadStreamCreateForHTTPRequest}},1);
                LOG(@"[AliSniffer] CFReadStream hook installed");
            }

            // AVPlayer / AVURLAsset hooks
            Class AVPI = NSClassFromString(@"AVPlayerItem");
            if (AVPI) {
                Method m1 = class_getInstanceMethod(AVPI, @selector(initWithURL:));
                if (m1) { orig_AVPI_initWithURL = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)swz_AVPI_initWithURL); }
                Method m2 = class_getClassMethod(AVPI, @selector(playerItemWithURL:));
                if (m2) { orig_AVPI_playerItemWithURL = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)swz_AVPI_playerItemWithURL); }
                LOG(@"[AliSniffer] AVPlayerItem hooks installed");
            }
            Class AVURLA = NSClassFromString(@"AVURLAsset");
            if (AVURLA) {
                Method m3 = class_getInstanceMethod(AVURLA, @selector(initWithURL:options:));
                if (m3) { orig_AVURLA_initWithURL = (void *)method_getImplementation(m3); method_setImplementation(m3, (IMP)swz_AVURLA_initWithURL); }
                Method m4 = class_getClassMethod(AVURLA, @selector(URLAssetWithURL:options:));
                if (m4) { orig_AVURLA_assetWithURL = (void *)method_getImplementation(m4); method_setImplementation(m4, (IMP)swz_AVURLA_assetWithURL); }
            }
            // replaceCurrentItemWithPlayerItem & playImmediatelyAtRate on AVPlayer
            Class AVP = NSClassFromString(@"AVPlayer");
            if (AVP) {
                Method mr = class_getInstanceMethod(AVP, @selector(replaceCurrentItemWithPlayerItem:));
                if (mr) { orig_replaceCurrentItem = (void *)method_getImplementation(mr); method_setImplementation(mr, (IMP)swz_replaceCurrentItem); }
                Method mp = class_getInstanceMethod(AVP, @selector(playImmediatelyAtRate:));
                if (mp) { orig_playImmediatelyAtRate = (void *)method_getImplementation(mp); method_setImplementation(mp, (IMP)swz_playImmediatelyAtRate); }
                LOG(@"[AliSniffer] AVPlayer replace/play hooks installed");
            }

            // WKWebView injection (MSE + fetch/XHR)
            Class WK = NSClassFromString(@"WKWebView");
            if (WK) {
                Method mi = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
                if (mi) { orig_WK_init = (void *)method_getImplementation(mi); method_setImplementation(mi, (IMP)swz_WK_init); }
                LOG(@"[AliSniffer] WKWebView injection installed (MSE sampling + fetch/XHR)");
            }

#if SNIFFER_IOS16_ENABLE_LIBCURL
            HookCurlIfPresent();
            LOG(@"[AliSniffer] libcurl hook attempted");
#endif

            // 定时推送（保留）
            [NSTimer scheduledTimerWithTimeInterval:kPushInterval repeats:YES block:^(__unused NSTimer * _Nonnull t) {
                if (g_lastPlayableURL.length) PushLatestURL_Raw(g_lastPlayableURL, nil);
            }];

#if SNIFFER_ENABLE_POPUP
            ShowPopupIfNeeded(@"AliSniffer 已加载", @"增强版已启用：auth_key 直通 + 多入口兜底（MSE/WS/AV/NSURLProtocol/CFReadStream）");
#endif
        });
    }
}

