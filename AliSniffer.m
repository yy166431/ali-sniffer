// AliSniffer.m —— 全量请求嗅探器 (直播 m3u8 + 回放 m3u8/mp4)
// 任何 NSURLSession 请求都会弹窗 URL，方便人工筛选。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

#pragma mark - 弹窗工具

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
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        UIViewController *rootVC = keyWindow.rootViewController;
        while (rootVC.presentedViewController) {
            rootVC = rootVC.presentedViewController;
        }
        [rootVC presentViewController:alert animated:YES completion:nil];
    });
}

static void ReportURL(NSString *u) {
    if (!u.length) return;
    NSString *low = u.lowercaseString;
    if ([low containsString:@"m3u8"]) {
        NSLog(@"[AliSniffer] M3U8: %@", u);
        ShowPopup(@"抓到 M3U8", u);
    } else if ([low containsString:@".mp4"]) {
        NSLog(@"[AliSniffer] MP4: %@", u);
        ShowPopup(@"抓到 MP4", u);
    } else {
        NSLog(@"[AliSniffer] URL: %@", u);
        // 可选：不弹所有，免得太吵；这里演示只弹关键的
        // ShowPopup(@"请求 URL", u);
    }
}

#pragma mark - Hook NSURLSession

static id (*orig_dataTaskReqCH)(id, SEL, NSURLRequest *, id);
static id swz_dataTaskReqCH(NSURLSession *self, SEL _cmd, NSURLRequest *req, id handler) {
    ReportURL(req.URL.absoluteString);
    return orig_dataTaskReqCH(self, _cmd, req, handler);
}

static id (*orig_dataTaskURLCH)(id, SEL, NSURL *, id);
static id swz_dataTaskURLCH(NSURLSession *self, SEL _cmd, NSURL *url, id handler) {
    ReportURL(url.absoluteString);
    return orig_dataTaskURLCH(self, _cmd, url, handler);
}

#pragma mark - 初始化

__attribute__((constructor))
static void init_sniffer(void) {
    @autoreleasepool {
        Class S = [NSURLSession class];
        if ([S instancesRespondToSelector:@selector(dataTaskWithRequest:completionHandler:)]) {
            Method m = class_getInstanceMethod(S, @selector(dataTaskWithRequest:completionHandler:));
            orig_dataTaskReqCH = (void*)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_dataTaskReqCH);
            NSLog(@"[AliSniffer] hook dataTaskWithRequest:completionHandler:");
        }
        if ([S instancesRespondToSelector:@selector(dataTaskWithURL:completionHandler:)]) {
            Method m = class_getInstanceMethod(S, @selector(dataTaskWithURL:completionHandler:));
            orig_dataTaskURLCH = (void*)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_dataTaskURLCH);
            NSLog(@"[AliSniffer] hook dataTaskWithURL:completionHandler:");
        }

        // 插件加载确认
        ShowPopup(@"AliSniffer 已加载", @"开始监控所有请求...");
        NSLog(@"[AliSniffer] ready (全量抓取).");
    }
}
