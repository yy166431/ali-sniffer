// AliSniffer_v3.m —— 只抓 m3u8：AliPlayer 入口 + NSURLProtocol 级别兜底
// 说明：仅打印/复制 m3u8，不改播放逻辑；能抓到“无后缀”的 m3u8（靠 MIME/内容判断）。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

#pragma mark - 工具

static void CopyToPasteboard(NSString *s) {
    if (!s.length) return;
    @try { [UIPasteboard generalPasteboard].string = s; } @catch (...) {}
    NSLog(@"[AliSniffer] copied: %@", s);
}

static void LogAndMaybeCopyURL(NSString *url, NSString *from) {
    if (!url.length) return;
    NSLog(@"[AliSniffer] URL (%@): %@", from, url);
    // 只复制“可能是 m3u8”的 URL（不强制包含后缀；由协议层再确认一次）
    NSString *low = url.lowercaseString;
    if ([low containsString:@"m3u8"] || [low containsString:@"playlist"]) {
        CopyToPasteboard(url);
    }
}

static NSString *ExtractURLStringFromObj(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:[NSString class]]) return (NSString *)obj;
    if ([obj isKindOfClass:[NSURL class]])    return [(NSURL *)obj absoluteString];
    @try {
        id v = nil;
        if ([obj respondsToSelector:@selector(URL)]) v = [obj performSelector:@selector(URL)];
        if (!v && [obj respondsToSelector:@selector(url)]) v = [obj performSelector:@selector(url)];
        if (!v && [obj respondsToSelector:@selector(urlString)]) v = [obj performSelector:@selector(urlString)];
        if (!v) v = [obj valueForKey:@"URL"];
        if (!v) v = [obj valueForKey:@"url"];
        if (!v) v = [obj valueForKey:@"urlString"];
        if ([v isKindOfClass:[NSString class]]) return (NSString *)v;
        if ([v isKindOfClass:[NSURL class]])    return [(NSURL *)v absoluteString];
    } @catch (...) {}
    return nil;
}

static void Swz(Class cls, SEL sel, IMP newIMP, IMP *origStore) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (origStore) *origStore = (IMP)method_getImplementation(m);
    method_setImplementation(m, newIMP);
}

#pragma mark - 1) AliPlayer/AVPUrlSource 快速入口（有就抓）

static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    NSString *u = ExtractURLStringFromObj(source);
    if (u.length) LogAndMaybeCopyURL(u, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

static void (*orig_AVP_setURL_NSURL)(id, SEL, NSURL *);
static void swz_AVP_setURL_NSURL(id self, SEL _cmd, NSURL *URL) {
    LogAndMaybeCopyURL(URL.absoluteString, @"AVPUrlSource.setURL:");
    orig_AVP_setURL_NSURL(self, _cmd, URL);
}

static void (*orig_AVP_setUrl_NSString)(id, SEL, NSString *);
static void swz_AVP_setUrl_NSString(id self, SEL _cmd, NSString *url) {
    LogAndMaybeCopyURL(url, @"AVPUrlSource.setUrl:");
    orig_AVP_setUrl_NSString(self, _cmd, url);
}

static int (*orig_Ali_prepareURL)(id, SEL, NSString *);
static int swz_Ali_prepareURL(id self, SEL _cmd, NSString *url) {
    LogAndMaybeCopyURL(url, @"AliyunVodPlayer.prepareWithURL");
    return orig_Ali_prepareURL(self, _cmd, url);
}
static int (*orig_Ali_playURL)(id, SEL, NSString *);
static int swz_Ali_playURL(id self, SEL _cmd, NSString *url) {
    LogAndMaybeCopyURL(url, @"AliyunVodPlayer.play");
    return orig_Ali_playURL(self, _cmd, url);
}

#pragma mark - 2) NSURLProtocol 级别兜底（识别 m3u8 的响应头/内容）

@interface SniffURLProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSessionDataTask *task;
@property (nonatomic, strong) NSMutableData *buffer; // 缓冲前几 KB 判定 #EXTM3U
@property (nonatomic, assign) BOOL decided;
@end

static NSString * const kHandledKey = @"AliSnifferHandled";

@implementation SniffURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    // 避免死循环
    if ([NSURLProtocol propertyForKey:kHandledKey inRequest:request]) return NO;
    // 仅 http/https
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) return NO;

    // 预判：请求头中 Accept 含 m3u8，优先拦
    NSString *accept = [request.allHTTPHeaderFields[@"Accept"] lowercaseString];
    if ([accept containsString:@"application/vnd.apple.mpegurl"] ||
        [accept containsString:@"application/x-mpegurl"]) {
        return YES;
    }
    // URL 包含提示词也拦（无后缀的情况由响应判断）
    NSString *u = request.URL.absoluteString.lowercaseString;
    if ([u containsString:@"m3u8"] || [u containsString:@"playlist"]) return YES;

    // 其他请求不提前拦（防止性能损耗），交给系统；但很多 m3u8 会带 Accept 头，上面已覆盖
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:kHandledKey inRequest:req];

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    // 把我们自己也塞到协议栈，保证后续子请求也能被识别（但有 handled 标记避免循环）
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:[SniffURLProtocol class]]) [arr insertObject:[SniffURLProtocol class] atIndex:0];
    cfg.protocolClasses = arr;

    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [session dataTaskWithRequest:req];
    self.buffer = [NSMutableData data];
    [self.task resume];
}

- (void)stopLoading {
    [self.task cancel];
    self.task = nil;
    self.buffer = nil;
}

#pragma mark - NSURLSessionDataDelegate

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
 didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {

    // 先把响应转发给原客户端
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];

    if (!self.decided) {
        self.decided = YES;
        // 1) 看 MIME
        NSString *mime = response.MIMEType.lowercaseString;
        if ([mime containsString:@"application/vnd.apple.mpegurl"] ||
            [mime containsString:@"application/x-mpegurl"]) {
            // 命中 m3u8，复制 URL
            CopyToPasteboard(dataTask.currentRequest.URL.absoluteString);
            NSLog(@"[AliSniffer] m3u8 by MIME: %@", dataTask.currentRequest.URL.absoluteString);
        }
    }
    if (completionHandler) completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    // 继续透传给原客户端
    [self.client URLProtocol:self didLoadData:data];

    // 如果前面没从 MIME 判定，再从内容判定（只看前几 KB）
    if (self.buffer && self.buffer.length < 16*1024) {
        [self.buffer appendData:data];
        if (self.buffer.length >= 7) { // "#EXTM3U"
            NSString *head = [[NSString alloc] initWithData:[self.buffer subdataWithRange:NSMakeRange(0, MIN(self.buffer.length, 2048))] encoding:NSUTF8StringEncoding];
            if (head && [head containsString:@"#EXTM3U"]) {
                CopyToPasteboard(dataTask.currentRequest.URL.absoluteString);
                NSLog(@"[AliSniffer] m3u8 by content: %@", dataTask.currentRequest.URL.absoluteString);
                self.buffer = nil; // 判定后不用再累计
            }
        }
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        [self.client URLProtocol:self didFailWithError:error];
    } else {
        [self.client URLProtocolDidFinishLoading:self];
    }
}

@end

#pragma mark - 3) 把 SniffURLProtocol 注入所有 Session 配置

static NSURLSessionConfiguration* (*orig_defCfg)(id, SEL);
static NSURLSessionConfiguration* swz_defCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_defCfg(self, _cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:[SniffURLProtocol class]]) [arr insertObject:[SniffURLProtocol class] atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}

static NSURLSessionConfiguration* (*orig_ephCfg)(id, SEL);
static NSURLSessionConfiguration* swz_ephCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_ephCfg(self, _cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:[SniffURLProtocol class]]) [arr insertObject:[SniffURLProtocol class] atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}

static NSURLSessionConfiguration* (*orig_bgCfg)(id, SEL, NSString *);
static NSURLSessionConfiguration* swz_bgCfg(id self, SEL _cmd, NSString *ident) {
    NSURLSessionConfiguration *cfg = orig_bgCfg(self, _cmd, ident);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:[SniffURLProtocol class]]) [arr insertObject:[SniffURLProtocol class] atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}

#pragma mark - 安装钩子

__attribute__((constructor))
static void _ali_sniffer_v3_init(void) {
    @autoreleasepool {
        // 入口：AliPlayer
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        if (AliPlayer && [AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
            Swz(AliPlayer, @selector(setUrlSource:), (IMP)swz_Ali_setUrlSource, (IMP *)&orig_Ali_setUrlSource);
            NSLog(@"[AliSniffer] hook AliPlayer.setUrlSource");
        }
        Class AVPUrlSource = NSClassFromString(@"AVPUrlSource");
        if (AVPUrlSource) {
            if ([AVPUrlSource instancesRespondToSelector:@selector(setURL:)]) {
                Swz(AVPUrlSource, @selector(setURL:), (IMP)swz_AVP_setURL_NSURL, (IMP *)&orig_AVP_setURL_NSURL);
                NSLog(@"[AliSniffer] hook AVPUrlSource.setURL:");
            }
            if ([AVPUrlSource instancesRespondToSelector:@selector(setUrl:)]) {
                Swz(AVPUrlSource, @selector(setUrl:), (IMP)swz_AVP_setUrl_NSString, (IMP *)&orig_AVP_setUrl_NSString);
                NSLog(@"[AliSniffer] hook AVPUrlSource.setUrl:");
            }
        }
        Class AliVod = NSClassFromString(@"AliyunVodPlayer");
        if (AliVod && [AliVod instancesRespondToSelector:@selector(prepareWithURL:)]) {
            Swz(AliVod, @selector(prepareWithURL:), (IMP)swz_Ali_prepareURL, (IMP *)&orig_Ali_prepareURL);
            NSLog(@"[AliSniffer] hook AliyunVodPlayer.prepareWithURL");
        }
        if (AliVod && [AliVod instancesRespondToSelector:@selector(play:)]) {
            Swz(AliVod, @selector(play:), (IMP)swz_Ali_playURL, (IMP *)&orig_Ali_playURL);
            NSLog(@"[AliSniffer] hook AliyunVodPlayer.play");
        }

        // 注入 NSURLProtocol：覆盖默认/临时/后台配置（Ali SDK 内部也会命中）
        Class Cfg = [NSURLSessionConfiguration class];
        if ([Cfg respondsToSelector:@selector(defaultSessionConfiguration)]) {
            Swz(Cfg, @selector(defaultSessionConfiguration), (IMP)swz_defCfg, (IMP *)&orig_defCfg);
            NSLog(@"[AliSniffer] inject defaultSessionConfiguration");
        }
        if ([Cfg respondsToSelector:@selector(ephemeralSessionConfiguration)]) {
            Swz(Cfg, @selector(ephemeralSessionConfiguration), (IMP)swz_ephCfg, (IMP *)&orig_ephCfg);
            NSLog(@"[AliSniffer] inject ephemeralSessionConfiguration");
        }
        if ([Cfg respondsToSelector:@selector(backgroundSessionConfiguration:)]) {
            Swz(Cfg, @selector(backgroundSessionConfiguration:), (IMP)swz_bgCfg, (IMP *)&orig_bgCfg);
            NSLog(@"[AliSniffer] inject backgroundSessionConfiguration:");
        } else if ([Cfg respondsToSelector:@selector(backgroundSessionConfigurationWithIdentifier:)]) {
            // 兼容旧签名
            Swz(Cfg, @selector(backgroundSessionConfigurationWithIdentifier:), (IMP)swz_bgCfg, (IMP *)&orig_bgCfg);
            NSLog(@"[AliSniffer] inject backgroundSessionConfigurationWithIdentifier:");
        }

        NSLog(@"[AliSniffer] ready (v3).");
    }
}
