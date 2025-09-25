// WxSniffer.m
// 适用于 TrollStore 注入微信，用于抓取 H5 播放器里的直播源请求
// 匹配 m3u8 / flv / rtmp

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>
#import "fishhook.h"

static NSURLSessionDataTask* (*orig_dataTaskWithRequest)(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *));

NSURLSessionDataTask* replaced_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *)) {
    NSString *url = request.URL.absoluteString;
    if ([url containsString:@".m3u8"] ||
        [url containsString:@".flv"]  ||
        [url hasPrefix:@"rtmp://"]) {

        NSLog(@"[WxSniffer] 捕获直播源请求: %@", url);

        // 写入本地文件，方便从 iFunbox / Filza 拷贝
        NSString *path = @"/var/mobile/Containers/Data/wx_stream_url.txt";
        [url writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];

        // 弹窗提醒（只提示一次，避免刷屏）
        dispatch_async(dispatch_get_main_queue(), ^{
            static BOOL showed = NO;
            if (!showed) {
                showed = YES;
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"抓到直播源"
                                                                               message:url
                                                                        preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    UIPasteboard.generalPasteboard.string = url;
                }]];
                [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
                [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:alert animated:YES completion:nil];
            }
        });
    }
    return orig_dataTaskWithRequest(self, _cmd, request, completionHandler);
}

__attribute__((constructor))
static void initSniffer() {
    NSLog(@"[WxSniffer] 插件已加载，准备嗅探 NSURLSession");
    rebind_symbols((struct rebinding[1]){{"__61-[NSURLSession dataTaskWithRequest:completionHandler:]_block_invoke", replaced_dataTaskWithRequest, (void *)&orig_dataTaskWithRequest}}, 1);
}
