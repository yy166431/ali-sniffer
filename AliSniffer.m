// AliSniffer.m - 酷牛 设备黑名单/签名/越狱检测 Bypass + PiP 画中画
// 注入方式: 轻松签 dylib 注入 (非越狱)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVKit/AVKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include "fishhook.h"

#pragma mark - 工具宏

#define KN_SWIZZLE_INSTANCE(cls, origSel, newSel) \
do { \
    Method orig = class_getInstanceMethod(cls, origSel); \
    Method new  = class_getInstanceMethod(cls, newSel);  \
    if (orig && new) method_exchangeImplementations(orig, new); \
} while(0)

#define KN_SWIZZLE_CLASS(cls, origSel, newSel) \
do { \
    Method orig = class_getClassMethod(cls, origSel); \
    Method new  = class_getClassMethod(cls, newSel);  \
    if (orig && new) method_exchangeImplementations(orig, new); \
} while(0)

// 遍历所有类，对含有指定方法的类批量 hook
static void hookAllClassesWithSelector(SEL origSel, SEL newSel, BOOL isClassMethod) {
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    for (unsigned int i = 0; i < count; i++) {
        Class cls = classes[i];
        Method m = isClassMethod
            ? class_getClassMethod(cls, origSel)
            : class_getInstanceMethod(cls, origSel);
        if (!m) continue;
        Method newM = isClassMethod
            ? class_getClassMethod(cls, newSel)
            : class_getInstanceMethod(cls, newSel);
        if (newM) method_exchangeImplementations(m, newM);
    }
    free(classes);
}

#pragma mark - NSURLProtocol 拦截 checkDeviceStatus

@interface KNDeviceStatusProtocol : NSURLProtocol
@end

@implementation KNDeviceStatusProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *url = request.URL.absoluteString;
    if ([url containsString:@"checkDeviceStatus"]) {
        if ([NSURLProtocol propertyForKey:@"KNHandled" inRequest:request]) return NO;
        return YES;
    }
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSDictionary *fakeData = @{
        @"code": @200,
        @"msg": @"success",
        @"data": @{
            @"isBlack": @0,
            @"is_black": @0,
            @"status": @1,
            @"deviceStatus": @1,
            @"banned": @0,
            @"isBanned": @0,
            @"black": @0,
        }
    };
    NSData *body = [NSJSONSerialization dataWithJSONObject:fakeData options:0 error:nil];
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc]
        initWithURL:self.request.URL
         statusCode:200
        HTTPVersion:@"HTTP/1.1"
       headerFields:@{@"Content-Type": @"application/json"}];

    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:body];
    [self.client URLProtocolDidFinishLoading:self];
}

- (void)stopLoading {}

@end

#pragma mark - 模型层: setIsBlack: 强制 NO

@interface NSObject (KNBlackBypass)
- (void)kn_setIsBlack:(BOOL)black;
- (BOOL)kn_isBlack;
@end

@implementation NSObject (KNBlackBypass)

- (void)kn_setIsBlack:(BOOL)black {
    [self kn_setIsBlack:NO];
}

- (BOOL)kn_isBlack {
    return NO;
}

@end

#pragma mark - 越狱检测 Bypass

@interface NSObject (KNJailbreakBypass)
- (BOOL)kn_isDeviceJailBreak;
- (NSString *)kn_getDeviceJailBreakString;
- (NSString *)kn_deviceJailBreakString;
@end

@implementation NSObject (KNJailbreakBypass)

- (BOOL)kn_isDeviceJailBreak {
    return NO;
}

- (NSString *)kn_getDeviceJailBreakString {
    return @"";
}

- (NSString *)kn_deviceJailBreakString {
    return @"";
}

@end

// stee_isJailbreak_1..7
@interface NSObject (KNSteeJailbreak)
- (BOOL)kn_stee_isJailbreak_stub;
@end

@implementation NSObject (KNSteeJailbreak)
- (BOOL)kn_stee_isJailbreak_stub { return NO; }
@end

#pragma mark - 调试检测 Bypass (WPK)

@interface NSObject (KNDebugBypass)
+ (BOOL)kn_isBeingDebugged;
@end

@implementation NSObject (KNDebugBypass)
+ (BOOL)kn_isBeingDebugged { return NO; }
@end

#pragma mark - 签名检测 Bypass

@interface NSObject (KNSignBypass)
- (void)kn_checkSignAuthIfNeed:(id)arg;
- (void)kn_initFilterConfigAndVerify;
- (void)kn_processSaveAppSignInfo:(id)arg;
@end

@implementation NSObject (KNSignBypass)

- (void)kn_checkSignAuthIfNeed:(id)arg {}
- (void)kn_initFilterConfigAndVerify {}
- (void)kn_processSaveAppSignInfo:(id)arg {}

@end

#pragma mark - PiP 画中画

// 绕过系统对 UIBackgroundModes 的检查
@interface AVPictureInPictureController (KNPiP)
+ (BOOL)kn_isPictureInPictureSupported;
@end

@implementation AVPictureInPictureController (KNPiP)
+ (BOOL)kn_isPictureInPictureSupported { return YES; }
@end

@interface NSObject (KNAliPiP)
- (void)kn_setPlayerView:(UIView *)view;
- (void)kn_triggerPiP;
- (void)kn_live_viewDidAppear:(BOOL)animated;
@end

@implementation NSObject (KNAliPiP)

// AliPlayer setPlayerView: 时自动开启内置 PiP 支持
- (void)kn_setPlayerView:(UIView *)view {
    [self kn_setPlayerView:view];
    if ([self respondsToSelector:@selector(setPictureInPictureEnable:)]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(self, @selector(setPictureInPictureEnable:), YES);
    }
}

// 直播页注入 PiP 按钮
- (void)kn_live_viewDidAppear:(BOOL)animated {
    [self kn_live_viewDidAppear:animated];
    UIViewController *vc = (UIViewController *)self;
    if (![vc isKindOfClass:[UIViewController class]]) return;
    if ([vc.view viewWithTag:9527]) return;

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.tag = 9527;
    btn.frame = CGRectMake(vc.view.bounds.size.width - 64, 88, 44, 44);
    btn.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
    btn.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.55];
    btn.layer.cornerRadius = 22;
    btn.tintColor = [UIColor whiteColor];
    if (@available(iOS 13.0, *)) {
        [btn setImage:[UIImage systemImageNamed:@"pip.enter"] forState:UIControlStateNormal];
    } else {
        [btn setTitle:@"PiP" forState:UIControlStateNormal];
    }
    [btn addTarget:self action:@selector(kn_triggerPiP) forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:btn];
}

// 点击按钮：遍历 ivar 找 AliPlayer 实例并触发 PiP
- (void)kn_triggerPiP {
    Class aliCls = objc_getClass("AliPlayer");
    if (!aliCls) return;
    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList([self class], &count);
    for (unsigned int i = 0; i < count; i++) {
        id val = object_getIvar(self, ivars[i]);
        if (val && [val isKindOfClass:aliCls]) {
            if ([val respondsToSelector:@selector(setPictureInPictureEnable:)]) {
                ((void (*)(id, SEL, BOOL))objc_msgSend)(val, @selector(setPictureInPictureEnable:), YES);
            }
            break;
        }
    }
    free(ivars);
}

@end

#pragma mark - 初始化入口

static void kn_setup(void) {
    // 1. 注册网络拦截
    [NSURLProtocol registerClass:[KNDeviceStatusProtocol class]];

    // 2. 遍历 hook setIsBlack: / isBlack
    hookAllClassesWithSelector(
        @selector(setIsBlack:), @selector(kn_setIsBlack:), NO);
    hookAllClassesWithSelector(
        @selector(isBlack), @selector(kn_isBlack), NO);

    // 3. 越狱检测
    hookAllClassesWithSelector(
        @selector(isDeviceJailBreak), @selector(kn_isDeviceJailBreak), NO);
    hookAllClassesWithSelector(
        @selector(getDeviceJailBreakString), @selector(kn_getDeviceJailBreakString), NO);
    hookAllClassesWithSelector(
        @selector(deviceJailBreakString), @selector(kn_deviceJailBreakString), NO);

    // stee_isJailbreak_1..7
    NSArray *steeSelNames = @[
        @"stee_isJailbreak_1", @"stee_isJailbreak_2", @"stee_isJailbreak_3",
        @"stee_isJailbreak_4", @"stee_isJailbreak_5", @"stee_isJailbreak_6",
        @"stee_isJailbreak_7"
    ];
    for (NSString *selName in steeSelNames) {
        hookAllClassesWithSelector(
            NSSelectorFromString(selName),
            @selector(kn_stee_isJailbreak_stub),
            NO);
    }

    // 4. WPK 调试检测
    Class wpkClass = objc_getClass("WPKOOMDetector");
    if (wpkClass) {
        KN_SWIZZLE_CLASS(wpkClass,
            @selector(isBeingDebugged),
            @selector(kn_isBeingDebugged));
    }

    // 5. 签名检测
    hookAllClassesWithSelector(
        @selector(checkSignAuthIfNeed:), @selector(kn_checkSignAuthIfNeed:), NO);
    hookAllClassesWithSelector(
        @selector(initFilterConfigAndVerify), @selector(kn_initFilterConfigAndVerify), NO);
    hookAllClassesWithSelector(
        @selector(processSaveAppSignInfo:), @selector(kn_processSaveAppSignInfo:), NO);

    // 6. PiP
    Class avPipCls = objc_getClass("AVPictureInPictureController");
    if (avPipCls) {
        KN_SWIZZLE_CLASS(avPipCls,
            @selector(isPictureInPictureSupported),
            @selector(kn_isPictureInPictureSupported));
    }
    Class aliCls = objc_getClass("AliPlayer");
    if (aliCls) {
        KN_SWIZZLE_INSTANCE(aliCls,
            @selector(setPlayerView:),
            @selector(kn_setPlayerView:));
    }
    Class liveCls = objc_getClass("LiveDetailController");
    if (liveCls) {
        KN_SWIZZLE_INSTANCE(liveCls,
            @selector(viewDidAppear:),
            @selector(kn_live_viewDidAppear:));
    }
}

// dylib 加载时自动执行
__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        kn_setup();
        NSLog(@"[KN] Hooks installed.");
    });
}
