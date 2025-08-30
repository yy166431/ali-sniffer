// AliSniffer.m —— 阿里云播放器抓取 m3u8/mp4 (全功能版)
// 功能: Hook AliPlayer / NSURLSession / CFNetwork
// 抓到后弹窗显示并可复制

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>
#import <CFNetwork/CFNetwork.h>
#import "fishhook.h"

#pragma mark - 弹窗工具

static void ShowPopup(NSString *title, NSString *url) {
    if (!url.length) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:url
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"复制"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = url;
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"关闭"
                                                  style:UIAlertActionStyleCancel
                                                handler:nil]];
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        UIViewController *rootVC = keyWindow.rootViewController;
        while (rootVC.presentedViewController) {
            rootVC = rootVC.presentedViewController;
        }
        [rootVC presentViewController:alert animated:YES completion:nil];
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
        NSLog(@"[AliSniffer] TS (%@): %@", from, url);
        // TS 不弹窗，避免打扰
    } else {
        NSLog(@"[AliSniffer] URL (%@): %@", from, url);
    }
}

#pragma mark - AliPlayer/AVP Hook

static NSString *ExtractURLStringFromObj(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:[NSString class]]) return obj;
    if ([obj isKindOfClass:[NSURL class]]) return [(NSURL *)obj absoluteString];
    @try {
        if ([obj respondsToSelector:@selector(URL)]) {
            id v = [obj performSelector:@selector(URL)];
            if ([v isKindOfClass:[NSURL class]]) return [(NSURL *)v absoluteString];
        }
        if ([obj respondsToSelector:@selector(url)]) {
            id v = [obj performSelector:@selector(url)];
            if ([v isKindOfClass:[NSString class]]) return v;
        }
    } @catch (...) {}
    return nil;
}

static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    NSString *u = ExtractURLStringFromObj(source);
    if (u) ReportURL(u, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

#pragma mark - NSURLSession Hook

static id (*orig_dataTaskReqCH)(id, SEL, NSURLRequest *, id);
static id swz_dataTaskReqCH(NSURLSession *self, SEL _cmd, NSURLRequest *req, id handler) {
    ReportURL(req.URL.absoluteString, @"NSURLSession");
    return orig_dataTaskReqCH(self, _cmd, req, handler);
}

#pragma mark - CFNetwork Hook

static CFReadStreamRef (*orig_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef alloc, CFHTTPMessageRef request);
CFReadStreamRef my_CFReadStreamCreateForHTTPRequest(CFAllocatorRef alloc, CFHTTPMessageRef request) {
    if (request) {
        CFURLRef urlRef = CFHTTPMessageCopyRequestURL(request);
        if (urlRef) {
            NSString *url = (__bridge_transfer NSString *)CFURLCopyString(urlRef);
            if (url) ReportURL(url, @"CFNetwork");
            CFRelease(urlRef);
        }
    }
    return orig_CFReadStreamCreateForHTTPRequest(alloc, request);
}

#pragma mark - 初始化

__attribute__((constructor))
static void init_sniffer(void) {
    @autoreleasepool {
        // Hook AliPlayer
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        if (AliPlayer && [AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
            Method m = class_getInstanceMethod(AliPlayer, @selector(setUrlSource:));
            orig_Ali_setUrlSource = (void*)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_Ali_setUrlSource);
            NSLog(@"[AliSniffer] hook AliPlayer.setUrlSource");
        }

        // Hook NSURLSession
        Class S = [NSURLSession class];
        if ([S instancesRespondToSelector:@selector(dataTaskWithRequest:completionHandler:)]) {
            Method m = class_getInstanceMethod(S, @selector(dataTaskWithRequest:completionHandler:));
            orig_dataTaskReqCH = (void*)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_dataTaskReqCH);
            NSLog(@"[AliSniffer] hook NSURLSession.dataTaskWithRequest:completionHandler:");
        }

        // Hook CFNetwork
        rebind_symbols((struct rebinding[1]){{"CFReadStreamCreateForHTTPRequest", my_CFReadStreamCreateForHTTPRequest, (void *)&orig_CFReadStreamCreateForHTTPRequest}}, 1);
        NSLog(@"[AliSniffer] hook CFReadStreamCreateForHTTPRequest");

        // 加载提示
        ShowPopup(@"AliSniffer 已加载", @"开始监控所有请求...");
        NSLog(@"[AliSniffer] ready (最终版).");
    }
}
