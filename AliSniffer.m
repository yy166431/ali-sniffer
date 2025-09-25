// WxSniffer.m
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "fishhook.h"

static NSURLSessionDataTask* (*orig_dataTaskWithRequest)(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *));

NSURLSessionDataTask* replaced_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *)) {
    NSString *url = request.URL.absoluteString;
    if ([url containsString:@".m3u8"] ||
        [url containsString:@".flv"]  ||
        [url hasPrefix:@"rtmp://"]) {

        NSLog(@"[WxSniffer] 捕获直播源: %@", url);

        // 写入文件，避免只看日志
        NSString *path = @"/var/mobile/Containers/Data/wx_stream_url.txt";
        [url writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];

        // 弹窗（可选，避免刷屏只弹一次）
        static BOOL showed = NO;
        if (!showed) {
            showed = YES;
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"抓到直播源"
                                                                               message:url
                                                                        preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    UIPasteboard.generalPasteboard.string = url;
                }]];
                [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
                [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:alert animated:YES completion:nil];
            });
        }
    }
    return orig_dataTaskWithRequest(self, _cmd, request, completionHandler);
}

// 延迟初始化，避免微信刚启动时直接 hook 崩溃
static void setupHook() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSLog(@"[WxSniffer] 延迟初始化，准备 fishhook");
        rebind_symbols((struct rebinding[1]){{
            "dataTaskWithRequest:completionHandler:",
            replaced_dataTaskWithRequest,
            (void *)&orig_dataTaskWithRequest
        }}, 1);
    });
}

__attribute__((constructor))
static void entry() {
    NSLog(@"[WxSniffer] dylib 已注入，等待应用启动完成…");
    // 延迟 3 秒再执行 hook
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        setupHook();
    });
}
