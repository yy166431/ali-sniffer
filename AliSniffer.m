//
//  AliSniffer.m
//  (基于你的原版，仅“增加识别”而不改动原有功能)
//
//  外部上报方式保持不变：NSNotification @"AliSnifferFoundURL"  (userInfo[@"url"])
//

#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>

#pragma mark - 工具

static inline NSString *HostOfURLString(NSString *u) {
    if (u.length == 0) return @"";
    NSURLComponents *c = [NSURLComponents componentsWithString:u];
    return c.host ?: @"";
}

static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"knyb.kuniunet.com",
            @"knydb.kuniunet.com",
            @"qiaohongb.kuniunet.com",
            @"v2.weizan.cn",
            // 新增：常见拉流域（仅增加，不影响原有逻辑）
            @"pull.kuniunet.com"
        ];
    });
    return a;
}

// 保持原函数名与用法，仅“加类型”不删原条件
static inline BOOL IsPlayable(NSString *u) {
    if (u.length == 0) return NO;
    NSString *s = u.lowercaseString;

    if ([s containsString:@"m3u8"] ||
        // 新增：DASH 清单 / CMAF 分片 / TS 分片
        [s containsString:@".mpd"] ||
        [s containsString:@".m4s"] ||
        [s containsString:@".ts"]  ||
        [s containsString:@".mp4"] ||
        [s containsString:@".flv"] ||
        [s hasPrefix:@"rtmp://"] || [s hasPrefix:@"rtmps://"] ||
        (([s hasPrefix:@"ws://"] || [s hasPrefix:@"wss://"]) && [s containsString:@".flv"])) {
        return YES;
    }
    NSString *h = HostOfURLString(s);
    for (NSString *w in WhitelistedHosts()) if ([h hasSuffix:w]) return YES;
    return NO;
}

// 保持原上报方式
static inline void ReportURL(NSString *urlString) {
    if (urlString.length == 0) return;
    [[NSNotificationCenter defaultCenter] postNotificationName:@"AliSnifferFoundURL"
                                                        object:nil
                                                      userInfo:@{@"url": urlString}];
    NSLog(@"[AliSniffer] HIT: %@", urlString);
}

#pragma mark - NSURLProtocol (名称/结构保持一致；仅增加识别分支)

@interface _SniffProto : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@property(nonatomic,strong) NSMutableData *buf;
@property(nonatomic,assign) BOOL shouted;
@end

@implementation _SniffProto

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"_SniffDone" inRequest:request]) return NO;
    NSString *sch = request.URL.scheme.lowercaseString;
    return [sch isEqualToString:@"http"] || [sch isEqualToString:@"https"];
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"_SniffDone" inRequest:req];

    self.buf = [NSMutableData dataWithCapacity:8*1024];
    self.shouted = NO;

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *ses = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [ses dataTaskWithRequest:req];
    [self.task resume];
}

- (void)stopLoading {
    [self.task cancel];
    self.task = nil;
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
 didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {

    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];

    if (!self.shouted) {
        NSString *mime = response.MIMEType.lowercaseString ?: @"";
        NSString *u = dataTask.currentRequest.URL.absoluteString.lowercaseString ?: @"";

        // 保留原有：HLS/FLV
        if ([mime containsString:@"mpegurl"]) {
            ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES;
        } else if ([mime containsString:@"x-flv"] || [mime containsString:@"/flv"]) {
            ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES;
        }
        // 新增：DASH 清单
        else if ([u containsString:@".mpd"] || [mime containsString:@"dash+xml"] || [mime containsString:@"application/dash+xml"]) {
            ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES;
        }
        // 新增：TS/CMAF 分片直拉
        else if ([mime containsString:@"video/mp2t"] ||
                 [mime containsString:@"application/octet-stream"] ||
                 [u containsString:@".ts"] || [u containsString:@".m4s"]) {
            ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES;
        }
    }
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];

    // 仅增加指纹识别；不改变原流程
    if (!self.shouted) {
        if (self.buf.length < 32*1024) [self.buf appendData:data];

        // 1) 文本 m3u8 / LL-HLS 标签（保持原有 + 扩展）
        NSString *head = [[NSString alloc] initWithData:self.buf encoding:NSUTF8StringEncoding];
        if (head) {
            if ([head containsString:@"#EXTM3U"] ||
                [head containsString:@"#EXT-X-PART"] ||
                [head containsString:@"#EXT-X-MAP"]) {
                ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; return;
            }
        }

        // 2) TS 指纹：188 对齐 0x47（粗判）
        const uint8_t *bytes = self.buf.bytes; NSUInteger n = self.buf.length;
        if (n >= 376) {
            BOOL looksTS = (bytes[0] == 0x47) &&
                           (bytes[188] == 0x47 || (n > 2*188 && bytes[2*188] == 0x47));
            if (looksTS) { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; return; }
        }

        // 3) CMAF/fMP4 指纹：'ftyp' / 'moof'
        if (n >= 12) {
            NSUInteger maxScan = MIN(n, (NSUInteger)4096);
            for (NSUInteger i=0; i+8<=maxScan; i++) {
                if (bytes[i+4]=='f' && bytes[i+5]=='t' && bytes[i+6]=='y' && bytes[i+7]=='p') { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; return; }
                if (bytes[i+4]=='m' && bytes[i+5]=='o' && bytes[i+6]=='o' && bytes[i+7]=='f') { ReportURL(dataTask.currentRequest.URL.absoluteString); self.shouted = YES; return; }
            }
        }
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}

@end

__attribute__((constructor))
static void _reg_proto(void) {
    [NSURLProtocol registerClass:[_SniffProto class]];
    NSLog(@"[AliSniffer] NSURLProtocol registered.");
}

#pragma mark - AVURLAsset（保底；不改原行为，仅在命中可播放时上报）

static id (*_orig_AVURLAsset_initWithURL_options)(id, SEL, NSURL *, NSDictionary *);
static id _hook_AVURLAsset_initWithURL_options(id self, SEL _cmd, NSURL *URL, NSDictionary *opts) {
    if (IsPlayable(URL.absoluteString)) {
        ReportURL(URL.absoluteString);
    }
    return ((id (*)(id, SEL, NSURL *, NSDictionary *))_orig_AVURLAsset_initWithURL_options)(self, _cmd, URL, opts);
}

__attribute__((constructor))
static void _hook_avasset(void) {
    Class c = [AVURLAsset class];
    SEL sel = @selector(initWithURL:options:);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    _orig_AVURLAsset_initWithURL_options = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)_hook_AVURLAsset_initWithURL_options);
    NSLog(@"[AliSniffer] Hooked AVURLAsset initWithURL:options:");
}

#pragma mark - WK 注入（保持你的结构与 handler 名，不改流程；只扩正则）

@interface _WKHandler : NSObject <WKScriptMessageHandler>
@end
@implementation _WKHandler
- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.name isEqualToString:@"_S"]) return;
    id body = message.body;
    NSString *u = [body isKindOfClass:NSString.class] ? body :
                  [body isKindOfClass:NSURL.class]    ? [(NSURL *)body absoluteString] : nil;
    if (u.length) ReportURL(u);
}
@end

static id (*orig_WK_init)(id, SEL, CGRect, WKWebViewConfiguration *);
static id swz_WK_init(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    // 保持你的原注入结构，仅扩 URL 正则
    if (cfg) {
        _WKHandler *h = [_WKHandler new];
        [cfg.userContentController addScriptMessageHandler:h name:@"_S"];
        NSString *js =
        // 仅扩展匹配类型：加入 .mpd / .m4s / .ts
        @"(function(){function r(u){try{if(u&&/(m3u8|\\.mpd(\\?|$)|\\.m4s(\\?|$)|\\.ts(\\?|$)|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)/i.test(u)){window.webkit.messageHandlers._S.postMessage(u);}}catch(e){}}"
         "var f=window.fetch;if(f){window.fetch=function(){var u=arguments[0];if(typeof u==='string'){r(u);}return f.apply(this,arguments).then(function(res){try{var u=res&&res.url;if(u)r(u);}catch(e){}return res;});};}"
         "var X=window.XMLHttpRequest;if(X){var o=X.prototype.open,s=X.prototype.send;X.prototype.open=function(m,u){try{this.__u=u;r(u);}catch(e){}return o.apply(this,arguments)};X.prototype.send=function(){try{r(this.__u);}catch(e){}return s.apply(this,arguments)};}"
         "if(window.HTMLMediaElement){var d=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');if(d&&d.set){Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{r(v);}catch(e){}return d.set.call(this,v);},get:d.get});}}"
        "})();";
        WKUserScript *sc = [[WKUserScript alloc] initWithSource:js injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
        [cfg.userContentController addUserScript:sc];
    }
    return orig_WK_init(self, _cmd, frame, cfg);
}

__attribute__((constructor))
static void _hook_wk(void) {
    Class c = [WKWebView class];
    SEL sel = @selector(initWithFrame:configuration:);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    orig_WK_init = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)swz_WK_init);
    NSLog(@"[AliSniffer] Hooked WKWebView initWithFrame:configuration:");
}
