// WxSniffer.m
// TrollStore 注入微信，捕获直播源 (m3u8 / flv / rtmp)
// 只弹窗显示并可复制，不写日志、不写文件

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>

#pragma mark - Helper
static void showStreamAlert(NSString *url, NSString *tag) {
    static BOOL showed = NO;
    if (showed) return;   // 避免重复刷屏
    showed = YES;

    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"抓到直播源"
                                                                       message:url
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            UIPasteboard.generalPasteboard.string = url;
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];

        UIViewController *rootVC = [UIApplication sharedApplication].keyWindow.rootViewController;
        [rootVC presentViewController:alert animated:YES completion:nil];
    });
}

#pragma mark - NSURLSession Hook
@implementation NSURLSession (Sniffer)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [NSURLSession class];
        SEL origSel = @selector(dataTaskWithRequest:completionHandler:);
        SEL newSel  = @selector(sniffer_dataTaskWithRequest:completionHandler:);

        Method orig = class_getInstanceMethod(cls, origSel);
        Method newM = class_getInstanceMethod(cls, newSel);

        method_exchangeImplementations(orig, newM);
    });
}

- (NSURLSessionDataTask *)sniffer_dataTaskWithRequest:(NSURLRequest *)request
                                    completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    NSString *url = request.URL.absoluteString;
    if ([url containsString:@".m3u8"] ||
        [url containsString:@".flv"]  ||
        [url hasPrefix:@"rtmp://"]) {
        showStreamAlert(url, @"NSURLSession");
    }
    return [self sniffer_dataTaskWithRequest:request completionHandler:completionHandler];
}

@end

#pragma mark - AVPlayer Hook
@implementation AVPlayer (Sniffer)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [AVPlayer class];
        SEL origSel = @selector(initWithURL:);
        SEL newSel  = @selector(sniffer_initWithURL:);

        Method orig = class_getInstanceMethod(cls, origSel);
        Method newM = class_getInstanceMethod(cls, newSel);

        method_exchangeImplementations(orig, newM);
    });
}

- (instancetype)sniffer_initWithURL:(NSURL *)URL {
    NSString *url = URL.absoluteString;
    if ([url containsString:@".m3u8"] ||
        [url containsString:@".flv"]  ||
        [url hasPrefix:@"rtmp://"]) {
        showStreamAlert(url, @"AVPlayer");
    }
    return [self sniffer_initWithURL:URL];
}

@end

#pragma mark - AVURLAsset Hook
@implementation AVURLAsset (Sniffer)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [AVURLAsset class];
        SEL origSel = @selector(initWithURL:options:);
        SEL newSel  = @selector(sniffer_initWithURL:options:);

        Method orig = class_getInstanceMethod(cls, origSel);
        Method newM = class_getInstanceMethod(cls, newSel);

        method_exchangeImplementations(orig, newM);
    });
}

- (instancetype)sniffer_initWithURL:(NSURL *)URL options:(NSDictionary<NSString *,id> *)options {
    NSString *url = URL.absoluteString;
    if ([url containsString:@".m3u8"] ||
        [url containsString:@".flv"]  ||
        [url hasPrefix:@"rtmp://"]) {
        showStreamAlert(url, @"AVURLAsset");
    }
    return [self sniffer_initWithURL:URL options:options];
}

@end
