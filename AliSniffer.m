// AliSniffer.m —— 阿里云播放器 m3u8 嗅探器（合体版）
// 功能：直链 Hook + NSURLProtocol 内容识别，无论 URL 是否带 .m3u8 都能抓
// 抓到后弹窗显示，并提供复制按钮

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

#pragma mark - 弹窗工具

static void ShowPopup(NSString *url) {
    if (!url.length) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"AliSniffer 抓到 URL"
                                                                       message:url
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = url;
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        UIViewController *rootVC = keyWindow.rootViewController;
        while (rootVC.presentedViewController) {
            rootVC = rootVC.presentedViewController;
        }
        [rootVC presentViewController:alert animated:YES completion:nil];
    });
}

static void CopyAndPopup(NSString *s, NSString *from) {
    if (!s.length) return;
    NSLog(@"[AliSniffer] URL (%@): %@", from, s);
    @try { [UIPasteboard generalPasteboard].string = s; } @catch (...) {}
    ShowPopup(s);
}

#pragma mark - 工具函数

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

#pragma mark - AliPlayer/AVPUrlSource Hook

static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    NSString *u = ExtractURLStringFromObj(source);
    if (u.length) CopyAndPopup(u, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

static int (*orig_Ali_prepareURL)(id, SEL, NSString *);
static int swz_Ali_prepareURL(id self, SEL _cmd, NSString *url) {
    if (url.length) CopyAndPopup(url, @"AliyunVodPlayer.prepareWithURL");
    return orig_Ali_prepareURL(self, _cmd, url);
}

static int (*orig_Ali_playURL)(id, SEL, NSString *);
static int swz_Ali_playURL(id self, SEL _cmd, NSString *url) {
    if (url.length) CopyAndPopup(url, @"AliyunVodPlayer.play");
    return orig_Ali_playURL(self, _cmd, url);
}

static void (*orig_AVP_setURL_NSURL)(id, SEL, NSURL *);
static void swz_AVP_setURL_NSURL(id self, SEL _cmd, NSURL *URL) {
    if (URL) CopyAndPopup(URL.absoluteString, @"AVPUrlSource.setURL");
    orig_AVP_setURL_NSURL(self, _cmd, URL);
}

static void (*orig_AVP_setUrl_NSString)(id, SEL, NSString *);
static void swz_AVP_setUrl_NSString(id self, SEL _cmd, NSString *url) {
    if (url.length) CopyAndPopup(url, @"AVPUrlSource.setUrl");
    orig_AVP_setUrl_NSString(self, _cmd, url);
}

#pragma mark - NSURLProtocol 拦截 m3u8

@interface SniffProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic,strong) NSURLSessionDataTask *task;
@property (nonatomic,strong) NSMutableData *buffer;
@property (nonatomic,assign) BOOL shown;
@end

@implementation SniffProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"SniffHandled" inRequest:request]) return NO;
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) return NO;
    return YES;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"SniffHandled" inRequest:req];
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:req];
    self.buffer = [NSMutableData data];
    [self.task resume];
}
- (void)stopLoading { [self.task cancel]; }
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
 didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    if (!self.shown) {
        NSString *mime = response.MIMEType.lowercaseString;
        if ([mime containsString:@"mpegurl"]) {
            CopyAndPopup(dataTask.currentRequest.URL.absoluteString, @"MIME sniff");
            self.shown = YES;
        }
    }
    completionHandler(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
    if (!self.shown && self.buffer.length < 4096) {
        [self.buffer appendData:data];
        NSString *head = [[NSString alloc] initWithData:self.buffer encoding:NSUTF8StringEncoding];
        if ([head containsString:@"#EXTM3U"]) {
            CopyAndPopup(dataTask.currentRequest.URL.absoluteString, @"Content sniff");
            self.shown = YES;
        }
    }
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

#pragma mark - 注入 NSURLProtocol

static NSURLSessionConfiguration* (*orig_def)(id,SEL);
static NSURLSessionConfiguration* swz_def(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_def(self,_cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:[SniffProtocol class]]) [arr insertObject:[SniffProtocol class] atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}

#pragma mark - 初始化

__attribute__((constructor))
static void init_sniffer(void) {
    @autoreleasepool {
        // Hook AliPlayer
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        if (AliPlayer && [AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
            Swz(AliPlayer, @selector(setUrlSource:), (IMP)swz_Ali_setUrlSource, (IMP *)&orig_Ali_setUrlSource);
            NSLog(@"[AliSniffer] hook AliPlayer.setUrlSource");
        }
        Class AVPUrlSource = NSClassFromString(@"AVPUrlSource");
        if (AVPUrlSource) {
            if ([AVPUrlSource instancesRespondToSelector:@selector(setURL:)]) {
                Swz(AVPUrlSource, @selector(setURL:), (IMP)swz_AVP_setURL_NSURL, (IMP *)&orig_AVP_setURL_NSURL);
                NSLog(@"[AliSniffer] hook AVPUrlSource.setURL");
            }
            if ([AVPUrlSource instancesRespondToSelector:@selector(setUrl:)]) {
                Swz(AVPUrlSource, @selector(setUrl:), (IMP)swz_AVP_setUrl_NSString, (IMP *)&orig_AVP_setUrl_NSString);
                NSLog(@"[AliSniffer] hook AVPUrlSource.setUrl");
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

        // 注入 NSURLProtocol
        Class Cfg = [NSURLSessionConfiguration class];
        if ([Cfg respondsToSelector:@selector(defaultSessionConfiguration)]) {
            Method m = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
            orig_def = (void*)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_def);
            NSLog(@"[AliSniffer] NSURLProtocol injected");
        }

        NSLog(@"[AliSniffer] ready (合体版).");
    }
}
