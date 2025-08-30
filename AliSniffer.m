// AliSniffer.m —— 全覆盖抓取 m3u8/mp4（AliPlayer + NSURLSessionTask + NSURLConnection + CFNetwork + 弹窗）
// 说明：
// - CFNetwork 相关通过 dlsym 动态解析，避免 Xcode 16 / iOS 18 SDK 链接期缺符号。
// - 命中 URL（m3u8/mp4）就弹窗并可复制；ts 只打日志避免打扰。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

#pragma mark - 弹窗 & 上报

static void ShowPopup(NSString *title, NSString *url) {
    if (url.length == 0) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:url
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"复制"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction * _Nonnull action) {
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
    if (url.length == 0) return;
    NSString *low = url.lowercaseString;
    if ([low containsString:@"m3u8"]) {
        NSLog(@"[AliSniffer] M3U8 (%@): %@", from, url);
        ShowPopup(@"抓到 M3U8", url);
    } else if ([low containsString:@".mp4"]) {
        NSLog(@"[AliSniffer] MP4 (%@): %@", from, url);
        ShowPopup(@"抓到 MP4", url);
    } else if ([low containsString:@".ts"]) {
        NSLog(@"[AliSniffer] TS (%@): %@", from, url); // ts 不弹窗
    } else {
        NSLog(@"[AliSniffer] URL (%@): %@", from, url);
    }
}

#pragma mark - 工具

static void Swizzle(Class cls, SEL sel, IMP newIMP, IMP *origStore) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (origStore) *origStore = method_getImplementation(m);
    method_setImplementation(m, newIMP);
}

static NSString *ExtractURLStringFromObj(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:[NSString class]]) return obj;
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

#pragma mark - ① AliPlayer / AliyunVodPlayer 直链入口

// AliPlayer: - (int)setUrlSource:(AVPUrlSource *)
static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    NSString *u = ExtractURLStringFromObj(source);
    if (u.length) ReportURL(u, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

// AliyunVodPlayer（老接口，少量项目仍在用）
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

#pragma mark - ② NSURLSessionTask 通杀

static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if ([self respondsToSelector:@selector(currentRequest)]) {
            NSURLRequest *req = [self performSelector:@selector(currentRequest)];
            if ([req isKindOfClass:[NSURLRequest class]]) {
                NSURL *u = req.URL;
                if (u) ReportURL(u.absoluteString, @"NSURLSessionTask.resume");
            }
        }
    } @catch (...) {}
    orig_task_resume(self, _cmd);
}

#pragma mark - ③ NSURLSession 常用构造

static id (*orig_dataTaskReqCH)(id, SEL, NSURLRequest *, id);
static id swz_dataTaskReqCH(NSURLSession *self, SEL _cmd, NSURLRequest *req, id handler) {
    if (req.URL) ReportURL(req.URL.absoluteString, @"NSURLSession.dataTaskWithRequest");
    return orig_dataTaskReqCH(self, _cmd, req, handler);
}

static id (*orig_dataTaskURLCH)(id, SEL, NSURL *, id);
static id swz_dataTaskURLCH(NSURLSession *self, SEL _cmd, NSURL *url, id handler) {
    if (url) ReportURL(url.absoluteString, @"NSURLSession.dataTaskWithURL");
    return orig_dataTaskURLCH(self, _cmd, url, handler);
}

#pragma mark - ④ NSURLConnection（旧接口）

static void (*orig_sendAsync)(id, SEL, NSURLRequest *, id, id);
static void swz_sendAsync(id cls, SEL _cmd, NSURLRequest *req, id queue, id handler) {
    if (req.URL) ReportURL(req.URL.absoluteString, @"NSURLConnection.sendAsync");
    orig_sendAsync(cls, _cmd, req, queue, handler);
}

#pragma mark - ⑤ CFNetwork C 层（fishhook + dlsym 解析）

// 原函数指针
static CFReadStreamRef (*orig_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef) = NULL;
static CFURLConnectionRef (*orig_CFURLConnectionCreateWithRequest)(CFAllocatorRef, CFURLRequestRef, CFURLConnectionClientCallBack, CFURLConnectionClientContext*) = NULL;

// dlsym 解析到的函数原型（可能在部分 SDK 不导出，故用弱解析）
typedef CFURLRef (*PFN_CFHTTPMessageCopyRequestURL)(CFHTTPMessageRef);
typedef CFURLRef (*PFN_CFURLRequestCopyURL)(CFURLRequestRef);
static PFN_CFHTTPMessageCopyRequestURL p_CFHTTPMessageCopyRequestURL = NULL;
static PFN_CFURLRequestCopyURL         p_CFURLRequestCopyURL = NULL;

static CFReadStreamRef hook_CFReadStreamCreateForHTTPRequest(CFAllocatorRef alloc, CFHTTPMessageRef request) {
    if (request && p_CFHTTPMessageCopyRequestURL) {
        CFURLRef urlRef = p_CFHTTPMessageCopyRequestURL(request);
        if (urlRef) {
            NSString *url = [(__bridge NSURL *)urlRef absoluteString];
            if (url.length) ReportURL(url, @"CFReadStreamCreateForHTTPRequest");
            CFRelease(urlRef);
        }
    }
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(alloc, request) : NULL;
}

static CFURLConnectionRef hook_CFURLConnectionCreateWithRequest(CFAllocatorRef alloc, CFURLRequestRef request, CFURLConnectionClientCallBack cb, CFURLConnectionClientContext *ctx) {
    if (request && p_CFURLRequestCopyURL) {
        CFURLRef urlRef = p_CFURLRequestCopyURL(request);
        if (urlRef) {
            NSString *url = [(__bridge NSURL *)urlRef absoluteString];
            if (url.length) ReportURL(url, @"CFURLConnectionCreateWithRequest");
            CFRelease(urlRef);
        }
    }
    return orig_CFURLConnectionCreateWithRequest ? orig_CFURLConnectionCreateWithRequest(alloc, request, cb, ctx) : NULL;
}

#pragma mark - 初始化

__attribute__((constructor))
static void _ali_sniffer_boot(void) {
    @autoreleasepool {
        // 1) AliPlayer / AliyunVodPlayer
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        if (AliPlayer && [AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
            Swizzle(AliPlayer, @selector(setUrlSource:), (IMP)swz_Ali_setUrlSource, (IMP *)&orig_Ali_setUrlSource);
            NSLog(@"[AliSniffer] hook AliPlayer.setUrlSource");
        }
        Class AliVod = NSClassFromString(@"AliyunVodPlayer");
        if (AliVod && [AliVod instancesRespondToSelector:@selector(prepareWithURL:)]) {
            Swizzle(AliVod, @selector(prepareWithURL:), (IMP)swz_Ali_prepareURL, (IMP *)&orig_Ali_prepareURL);
            NSLog(@"[AliSniffer] hook AliyunVodPlayer.prepareWithURL");
        }
        if (AliVod && [AliVod instancesRespondToSelector:@selector(play:)]) {
            Swizzle(AliVod, @selector(play:), (IMP)swz_Ali_playURL, (IMP *)&orig_Ali_playURL);
            NSLog(@"[AliSniffer] hook AliyunVodPlayer.play");
        }

        // 2) NSURLSessionTask.resume
        Class Task = NSClassFromString(@"NSURLSessionTask");
        if (Task && class_getInstanceMethod(Task, @selector(resume))) {
            Swizzle(Task, @selector(resume), (IMP)swz_task_resume, (IMP *)&orig_task_resume);
            NSLog(@"[AliSniffer] hook NSURLSessionTask.resume");
        }

        // 3) NSURLSession 两个常用构造
        Class S = [NSURLSession class];
        if (S && [S instancesRespondToSelector:@selector(dataTaskWithRequest:completionHandler:)]) {
            Swizzle(S, @selector(dataTaskWithRequest:completionHandler:), (IMP)swz_dataTaskReqCH, (IMP *)&orig_dataTaskReqCH);
            NSLog(@"[AliSniffer] hook NSURLSession.dataTaskWithRequest:completionHandler:");
        }
        if (S && [S instancesRespondToSelector:@selector(dataTaskWithURL:completionHandler:)]) {
            Swizzle(S, @selector(dataTaskWithURL:completionHandler:), (IMP)swz_dataTaskURLCH, (IMP *)&orig_dataTaskURLCH);
            NSLog(@"[AliSniffer] hook NSURLSession.dataTaskWithURL:completionHandler:");
        }

        // 4) NSURLConnection（旧接口）
        Class Conn = [NSURLConnection class];
        if (Conn && class_getClassMethod(Conn, @selector(sendAsynchronousRequest:queue:completionHandler:))) {
            Swizzle(object_getClass(Conn), @selector(sendAsynchronousRequest:queue:completionHandler:), (IMP)swz_sendAsync, (IMP *)&orig_sendAsync);
            NSLog(@"[AliSniffer] hook NSURLConnection.sendAsynchronousRequest");
        }

        // 5) CFNetwork：运行时解析可用符号，再用 fishhook 绑定
        void *hCF = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_NOW);
        if (hCF) {
            p_CFHTTPMessageCopyRequestURL = (PFN_CFHTTPMessageCopyRequestURL)dlsym(hCF, "CFHTTPMessageCopyRequestURL");
            p_CFURLRequestCopyURL         = (PFN_CFURLRequestCopyURL)        dlsym(hCF, "CFURLRequestCopyURL");
        }
        struct rebinding rbs[2] = {
            {"CFReadStreamCreateForHTTPRequest", (void *)hook_CFReadStreamCreateForHTTPRequest, (void **)&orig_CFReadStreamCreateForHTTPRequest},
            {"CFURLConnectionCreateWithRequest", (void *)hook_CFURLConnectionCreateWithRequest, (void **)&orig_CFURLConnectionCreateWithRequest},
        };
        rebind_symbols(rbs, 2);
        NSLog(@"[AliSniffer] fishhook CFNetwork installed");

        // 加载提示
        ShowPopup(@"AliSniffer 已加载", @"开始监控所有网络请求…");
        NSLog(@"[AliSniffer] ready.");
    }
}
