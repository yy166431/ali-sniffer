// AliSniffer.m —— 阿里云 m3u8/mp4 抓取（无 fishhook 版本）
// 思路：
// 1) Hook AliPlayer/AliyunVodPlayer/AVPUrlSource 直链入口；
// 2) 通杀 Hook -[NSURLSessionTask resume]，在任何请求真正发起前抓 URL；
// 3) 抓到后弹窗显示并可一键复制。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

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
        NSLog(@"[AliSniffer] TS (%@): %@", from, url); // TS 不弹窗，避免骚扰
    } else {
        NSLog(@"[AliSniffer] URL (%@): %@", from, url);
    }
}

#pragma mark - 工具

static void Swz(Class cls, SEL sel, IMP newIMP, IMP *origStore) {
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

#pragma mark - ② NSURLSessionTask 通杀

// iOS 里 NSURLSessionTask 实例方法 -resume 会在真正发起网络前调用
// 我们在这里读取 task.currentRequest.URL，所有网络库最终都会走到这里
static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if ([self respondsToSelector:@selector(currentRequest)]) {
            NSURLRequest *req = [self performSelector:@selector(currentRequest)];
            if ([req isKindOfClass:[NSURLRequest class]]) {
                NSString *u = req.URL.absoluteString ?: @"";
                if (u.length) ReportURL(u, @"NSURLSessionTask.resume");
            }
        }
    } @catch (...) {}
    orig_task_resume(self, _cmd);
}

#pragma mark - 初始化

__attribute__((constructor))
static void _ali_sniffer_init(void) {
    @autoreleasepool {
        // 直链入口
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        if (AliPlayer && [AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
            Swz(AliPlayer, @selector(setUrlSource:), (IMP)swz_Ali_setUrlSource, (IMP *)&orig_Ali_setUrlSource);
            NSLog(@"[AliSniffer] hook AliPlayer.setUrlSource");
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

        // 通杀 NSURLSessionTask.resume
        Class Task = NSClassFromString(@"NSURLSessionTask");
        if (Task && class_getInstanceMethod(Task, @selector(resume))) {
            Swz(Task, @selector(resume), (IMP)swz_task_resume, (IMP *)&orig_task_resume);
            NSLog(@"[AliSniffer] hook NSURLSessionTask.resume");
        }

        // 加载提示
        ShowPopup(@"AliSniffer 已加载", @"开始监控所有请求…");
        NSLog(@"[AliSniffer] ready.");
    }
}
