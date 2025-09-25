// WxSniffer.m
// 仅 hook NSURLSession，匹配 m3u8 / flv / rtmp，弹窗复制
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

#pragma mark - 工具：找到可展示弹窗的顶层VC
static UIViewController *wxsniffer_topVC(void) {
    UIWindow *win = UIApplication.sharedApplication.keyWindow;
    if (!win) {
        for (UIWindowScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in ((UIWindowScene *)scene).windows) { if (w.isKeyWindow) { win = w; break; } }
            }
        }
    }
    UIViewController *vc = win.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc ?: win.rootViewController;
}

static void wxsniffer_showAlert(NSString *url) {
    static BOOL shown = NO;          // 只弹一次，防止刷屏
    if (shown) return;
    shown = YES;

    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"抓到直播源"
                                                                   message:url
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            UIPasteboard.generalPasteboard.string = url;
        }]];
        [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        [wxsniffer_topVC() presentViewController:a animated:YES completion:nil];
    });
}

static inline BOOL wxsniffer_isStreamURL(NSString *u) {
    if (u.length == 0) return NO;
    return ([u containsString:@".m3u8"] ||
            [u containsString:@".flv"]  ||
            [u hasPrefix:@"rtmp://"]);
}

#pragma mark - NSURLSession Hook（swizzle）
@interface NSURLSession (WxSniffer)
@end

@implementation NSURLSession (WxSniffer)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [NSURLSession class];
        SEL origSel = @selector(dataTaskWithRequest:completionHandler:);
        SEL newSel  = @selector(wxsniffer_dataTaskWithRequest:completionHandler:);

        Method orig = class_getInstanceMethod(cls, origSel);
        Method neu  = class_getInstanceMethod(cls, newSel);
        method_exchangeImplementations(orig, neu);
    });
}

- (NSURLSessionDataTask *)wxsniffer_dataTaskWithRequest:(NSURLRequest *)request
                                     completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler
{
    NSString *url = request.URL.absoluteString ?: @"";
    if (wxsniffer_isStreamURL(url)) {
        wxsniffer_showAlert(url);
    }
    // 调回原实现（已交换）
    return [self wxsniffer_dataTaskWithRequest:request completionHandler:completionHandler];
}

@end
