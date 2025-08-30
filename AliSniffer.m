// AliSniffer.m —— 阿里云播放器抓取 m3u8/mp4 (合体+修正版)
// 功能: Hook AliPlayer / NSURLSession / CFNetwork(C函数) / 弹窗复制
// 说明：已修正 CFURL* 取字符串的写法（使用 CFURLGetString）

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CFNetwork/CFNetwork.h>
#import "fishhook.h"

#pragma mark - 弹窗 & 报告

static void ShowPopup(NSString *title, NSString *url) {
    if (!url.length) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:url
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = url;
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *win = [UIApplication sharedApplication].keyWindow;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        [vc presentViewController:alert animated:YES completion:nil];
    });
}

static void ReportURL(NSString *url, NSString *from) {
    if (!url.length) return;
    NSString *low = url.lowercaseString;
    if ([low containsString:@"m3u8"]) {
        NSLog(@"[AliSniffer] M3U8 (%@): %@", from, url);
        ShowPopup(@"抓到 M3U8", url);
    } else if ([low containsString:@".mp4"]) {
        NSLog(@"[AliSniffer] MP4 (%@): %@", from, url);
        ShowPopup(@"抓到 MP4", url);
    } else if ([low containsString:@".ts"]) {
        NSLog(@"[AliSniffer] TS (%@): %@", from, url); // TS 不弹窗
    } else {
        NSLog(@"[AliSniffer] URL (%@): %@", from, url);
    }
}

#pragma mark - 工具

static NSString *ExtractURLStringFromObj(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:[NSString class]]) return (NSString *)obj;
    if ([obj isKindOfClass:[NSURL class]])    return [(NSURL *)obj absoluteString];
    @try {
        id v = nil;
        if ([obj respondsToSelector:@selector(URL)])       v = [obj performSelector:@selector(URL)];
        if (!v && [obj respondsToSelector:@selector(url)]) v = [obj performSelector:@selector(url)];
        if ([v isKindOfClass:[NSString class]]) return v;
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

#pragma mark - ① AliPlayer / AVPUrlSource / AliyunVodPlayer

// AliPlayer: - (int)setUrlSource:(AVPUrlSource *)
static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    NSString *u = ExtractURLStringFromObj(source);
    if (u.length) ReportURL(u, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

// AliyunVodPlayer: - (int)prepareWithURL:(NSString *)
static int (*orig_Ali_prepareURL)(id, SEL, NSString *);
static int swz_Ali_prepareURL(id self, SEL _cmd, NSString *url) {
    if (url.length) ReportURL(url, @"AliyunVodPlayer.prepareWithURL");
    return orig_Ali_prepareURL(self, _cmd, url);
}

// AliyunVodPlayer: - (int)play:(NSString *)
static int (*orig_Ali_playURL)(id, SEL, NSString *);
static int swz_Ali_playURL(id self, SEL _cmd, NSString *url) {
    if (url.length) ReportURL(url, @"AliyunVodPlayer.play");
    return orig_Ali_playURL(self, _cmd, url);
}

#pragma mark - ② NSURLSession（常用接口）

static id (*orig_dataTaskReqCH)(id, SEL, NSURLRequest *, id);
static id swz_dataTaskReqCH(NSURLSession *self, SEL _cmd, NSURLRequest *req, id handler) {
    ReportURL(req.URL.absoluteString, @"NSURLSession");
    return orig_dataTaskReqCH(self, _cmd, req, handler);
}

static id (*orig_dataTaskURLCH)(id, SEL, NSURL *, id);
static id swz_dataTaskURLCH(NSURLSession *self, SEL _cmd, NSURL *url, id handler) {
    ReportURL(url.absoluteString, @"NSURLSession");
    return orig_dataTaskURLCH(self, _cmd, url, handler);
}

#pragma mark - ③ CFNetwork C 函数（最底层兜底）

static CFReadStreamRef (*orig_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);

static CFReadStreamRef my_CFReadStreamCreateForHTTPRequest(CFAllocatorRef alloc, CFHTTPMessageRef request) {
    if (request) {
        CFURLRef urlRef = CFHTTPMessageCopyRequestURL(request);
        if (urlRef) {
            // ⚠️ 正确：CFURLGetString -> CFStringRef（非retain），转 NSString 再 copy 一份
            CFStringRef cfStr = CFURLGetString(urlRef);
            NSString *url = cfStr ? [(__bridge NSString *)cfStr copy] : nil;
            if (url.length) ReportURL(url, @"CFNetwork");
            CFRelease(urlRef);
        }
    }
    return orig_CFReadStreamCreateForHTTPRequest(alloc, request);
}

#pragma mark - 初始化

__attribute__((constructor))
static void _ali_sniffer_init(void) {
    @autoreleasepool {
        // AliPlayer
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        if (AliPlayer && [AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
            Swz(AliPlayer, @selector(setUrlSource:), (IMP)swz_Ali_setUrlSource, (IMP *)&orig_Ali_setUrlSource);
            NSLog(@"[AliSniffer] hook AliPlayer.setUrlSource");
        }
        // AliyunVodPlayer（部分项目仍用）
        Class AliVod = NSClassFromString(@"AliyunVodPlayer");
        if (AliVod && [AliVod instancesRespondToSelector:@selector(prepareWithURL:)]) {
            Swz(AliVod, @selector(prepareWithURL:), (IMP)swz_Ali_prepareURL, (IMP *)&orig_Ali_prepareURL);
            NSLog(@"[AliSniffer] hook AliyunVodPlayer.prepareWithURL");
        }
        if (AliVod && [AliVod instancesRespondToSelector:@selector(play:)]) {
            Swz(AliVod, @selector(play:), (IMP)swz_Ali_playURL, (IMP *)&orig_Ali_playURL);
            NSLog(@"[AliSniffer] hook AliyunVodPlayer.play");
        }

        // NSURLSession (两个带 completionHandler 的常用入口)
        Class S = [NSURLSession class];
        if ([S instancesRespondToSelector:@selector(dataTaskWithRequest:completionHandler:)]) {
            Swz(S, @selector(dataTaskWithRequest:completionHandler:), (IMP)swz_dataTaskReqCH, (IMP *)&orig_dataTaskReqCH);
            NSLog(@"[AliSniffer] hook NSURLSession.dataTaskWithRequest:completionHandler:");
        }
        if ([S instancesRespondToSelector:@selector(dataTaskWithURL:completionHandler:)]) {
            Swz(S, @selector(dataTaskWithURL:completionHandler:), (IMP)swz_dataTaskURLCH, (IMP *)&orig_dataTaskURLCH);
            NSLog(@"[AliSniffer] hook NSURLSession.dataTaskWithURL:completionHandler:");
        }

        // CFNetwork C 函数（fishhook）
        struct rebinding rb = {"CFReadStreamCreateForHTTPRequest", (void *)my_CFReadStreamCreateForHTTPRequest, (void **)&orig_CFReadStreamCreateForHTTPRequest};
        rebind_symbols(&rb, 1);
        NSLog(@"[AliSniffer] hook CFReadStreamCreateForHTTPRequest");

        // 加载提示
        ShowPopup(@"AliSniffer 已加载", @"开始监控所有请求…");
        NSLog(@"[AliSniffer] ready.");
    }
}
