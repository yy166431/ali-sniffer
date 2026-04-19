// AliSniffer.m - 酷牛 v6.4.1 设备黑名单/指纹/签名/越狱检测 Bypass + PiP 画中画
// 注入方式: 轻松签/巨魔 dylib 注入 (非越狱)
// 更新: 2026-04 v2.2 — 兼容 iOS 14+，修复闪退

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVKit/AVKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include "fishhook.h"

#pragma mark - 工具宏

// 安全 swizzle: 先 addMethod 防止 hook 到父类
static void kn_swizzle(Class cls, SEL origSel, SEL newSel) {
    if (!cls) return;
    Method origMethod = class_getInstanceMethod(cls, origSel);
    Method newMethod  = class_getInstanceMethod(cls, newSel);
    if (!origMethod || !newMethod) return;
    if (class_addMethod(cls, origSel,
            method_getImplementation(newMethod),
            method_getTypeEncoding(newMethod))) {
        class_replaceMethod(cls, newSel,
            method_getImplementation(origMethod),
            method_getTypeEncoding(origMethod));
    } else {
        method_exchangeImplementations(origMethod, newMethod);
    }
}

static void kn_swizzleClass(Class cls, SEL origSel, SEL newSel) {
    if (!cls) return;
    Method origMethod = class_getClassMethod(cls, origSel);
    Method newMethod  = class_getClassMethod(cls, newSel);
    if (!origMethod || !newMethod) return;
    // class method 实际在 meta class 上
    Class meta = object_getClass(cls);
    if (class_addMethod(meta, origSel,
            method_getImplementation(newMethod),
            method_getTypeEncoding(newMethod))) {
        class_replaceMethod(meta, newSel,
            method_getImplementation(origMethod),
            method_getTypeEncoding(origMethod));
    } else {
        method_exchangeImplementations(origMethod, newMethod);
    }
}

// 遍历所有类 hook (仅用于 app 自定义的、不会和系统冲突的 selector)
static void hookAppClassesWithSelector(SEL origSel, SEL newSel) {
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    for (unsigned int i = 0; i < count; i++) {
        Class cls = classes[i];
        // 跳过系统框架类，只 hook app 自己的
        const char *name = class_getName(cls);
        if (!name) continue;
        // 系统类通常以 NS/UI/CF/CA/AV/GDT/_ 开头，跳过
        if (name[0] == '_') continue;
        if (strncmp(name, "NS", 2) == 0) continue;
        if (strncmp(name, "UI", 2) == 0) continue;
        if (strncmp(name, "CF", 2) == 0) continue;
        if (strncmp(name, "CA", 2) == 0) continue;
        if (strncmp(name, "OS", 2) == 0) continue;
        if (strncmp(name, "WK", 2) == 0) continue;
        if (strncmp(name, "GDT", 3) == 0) continue;

        Method m = class_getInstanceMethod(cls, origSel);
        if (!m) continue;
        // 确保这个方法是这个类自己声明的，不是继承来的
        Method superM = NULL;
        Class superCls = class_getSuperclass(cls);
        if (superCls) superM = class_getInstanceMethod(superCls, origSel);
        if (superM && m == superM) continue;

        Method newM = class_getInstanceMethod(cls, newSel);
        if (!newM) continue;
        method_exchangeImplementations(m, newM);
    }
    free(classes);
}

#pragma mark - 随机设备 ID 生成

static NSString *kn_persistentRandomUDID(void) {
    static NSString *cachedID = nil;
    if (cachedID) return cachedID;

    NSString *key = @"kn_random_udid_v2";
    NSString *stored = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (stored.length > 0) {
        cachedID = stored;
        return cachedID;
    }

    cachedID = [[NSUUID UUID] UUIDString];
    [[NSUserDefaults standardUserDefaults] setObject:cachedID forKey:key];
    [[NSUserDefaults standardUserDefaults] synchronize];
    return cachedID;
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

    NSMutableURLRequest *handled = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"KNHandled" inRequest:handled];

    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:body];
    [self.client URLProtocolDidFinishLoading:self];
}

- (void)stopLoading {}

@end

#pragma mark - 模型层: setIsBlack: / isBlack

@interface NSObject (KNBlackBypass)
- (void)kn_setIsBlack:(BOOL)black;
- (BOOL)kn_isBlack;
@end

@implementation NSObject (KNBlackBypass)
- (void)kn_setIsBlack:(BOOL)black { [self kn_setIsBlack:NO]; }
- (BOOL)kn_isBlack { return NO; }
@end

#pragma mark - 越狱检测 Bypass

@interface NSObject (KNJailbreakBypass)
- (BOOL)kn_isDeviceJailBreak;
- (NSString *)kn_getDeviceJailBreakString;
- (NSString *)kn_deviceJailBreakString;
@end

@implementation NSObject (KNJailbreakBypass)
- (BOOL)kn_isDeviceJailBreak { return NO; }
- (NSString *)kn_getDeviceJailBreakString { return @""; }
- (NSString *)kn_deviceJailBreakString { return @""; }
@end

@interface NSObject (KNSteeJailbreak)
- (BOOL)kn_stee_isJailbreak_stub;
@end

@implementation NSObject (KNSteeJailbreak)
- (BOOL)kn_stee_isJailbreak_stub { return NO; }
@end

#pragma mark - 调试检测 Bypass

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

#pragma mark - TuringShield 指纹 Bypass

@interface NSObject (KNTuringBypass)
- (void)kn_getFingerprintOnlineWithCompletionHandler:(id)handler;
- (NSDictionary *)kn_blockedFingerprintConfig;
- (void)kn_setBlockedFingerprintConfig:(NSDictionary *)config;
@end

@implementation NSObject (KNTuringBypass)

- (void)kn_getFingerprintOnlineWithCompletionHandler:(id)handler {
    // handler 是 block: void(^)(TuringDeviceFingerprintUNBC *)
    // 传 nil 让指纹采集静默失败
    if (handler) {
        void(^blk)(id) = (void(^)(id))handler;
        blk(nil);
    }
}

- (NSDictionary *)kn_blockedFingerprintConfig {
    return @{};
}

- (void)kn_setBlockedFingerprintConfig:(NSDictionary *)config {
    [self kn_setBlockedFingerprintConfig:@{}];
}

@end

#pragma mark - OpenUDID Bypass

@interface NSObject (KNOpenUDIDBypass)
+ (NSString *)kn_openUDIDString;
- (NSString *)kn_openUDIDValue;
@end

@implementation NSObject (KNOpenUDIDBypass)
+ (NSString *)kn_openUDIDString { return kn_persistentRandomUDID(); }
- (NSString *)kn_openUDIDValue { return kn_persistentRandomUDID(); }
@end

#pragma mark - GDT 越狱检测

@interface NSObject (KNGDTBypass)
- (BOOL)kn_isJailBroken;
@end

@implementation NSObject (KNGDTBypass)
- (BOOL)kn_isJailBroken { return NO; }
@end

#pragma mark - PiP 画中画

@interface AVPictureInPictureController (KNPiP)
+ (BOOL)kn_isPictureInPictureSupported;
@end

@implementation AVPictureInPictureController (KNPiP)
+ (BOOL)kn_isPictureInPictureSupported { return YES; }
@end

@interface NSObject (KNSJPiP)
- (void)kn_sj_setPlayerView:(UIView *)view;
- (void)kn_triggerSJPiP;
- (void)kn_live_viewDidAppear:(BOOL)animated;
@end

@implementation NSObject (KNSJPiP)

- (void)kn_sj_setPlayerView:(UIView *)view {
    [self kn_sj_setPlayerView:view];
    if ([self respondsToSelector:@selector(setPictureInPictureEnable:)]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(self, @selector(setPictureInPictureEnable:), YES);
    }
}

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
    [btn setTitle:@"PiP" forState:UIControlStateNormal];
    [btn.titleLabel setFont:[UIFont boldSystemFontOfSize:13]];
    [btn addTarget:self action:@selector(kn_triggerSJPiP) forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:btn];
}

- (void)kn_triggerSJPiP {
    NSArray *playerClassNames = @[@"SJBaseVideoPlayer", @"SJVideoPlayer", @"AliPlayer"];
    for (NSString *clsName in playerClassNames) {
        Class playerCls = objc_getClass(clsName.UTF8String);
        if (!playerCls) continue;
        unsigned int count = 0;
        Ivar *ivars = class_copyIvarList([self class], &count);
        for (unsigned int i = 0; i < count; i++) {
            id val = object_getIvar(self, ivars[i]);
            if (val && [val isKindOfClass:playerCls]) {
                if ([val respondsToSelector:@selector(setPictureInPictureEnable:)]) {
                    ((void (*)(id, SEL, BOOL))objc_msgSend)(val, @selector(setPictureInPictureEnable:), YES);
                }
                if ([val respondsToSelector:@selector(pipPlayer)]) {
                    id pip = ((id (*)(id, SEL))objc_msgSend)(val, @selector(pipPlayer));
                    if (pip && [pip respondsToSelector:@selector(startPictureInPicture)]) {
                        ((void (*)(id, SEL))objc_msgSend)(pip, @selector(startPictureInPicture));
                    }
                }
                free(ivars);
                return;
            }
        }
        free(ivars);
    }
}

@end

#pragma mark - fishhook: 文件路径检测 bypass

static int (*orig_access)(const char *, int);
static int kn_access(const char *path, int mode) {
    if (path) {
        // 快速前缀检查，避免频繁创建 NSString
        if (strstr(path, "Cydia") ||
            strstr(path, "MobileSubstrate") ||
            strstr(path, "sshd") ||
            strstr(path, "/var/jb") ||
            strstr(path, "/etc/apt") ||
            strstr(path, "tweaksupport")) {
            return -1;
        }
    }
    return orig_access(path, mode);
}

#pragma mark - 初始化入口

static void kn_setup(void) {
    @try {
        // 1. 网络拦截
        [NSURLProtocol registerClass:[KNDeviceStatusProtocol class]];

        // 2. isBlack (app 自定义 selector，安全遍历)
        hookAppClassesWithSelector(@selector(setIsBlack:), @selector(kn_setIsBlack:));
        hookAppClassesWithSelector(@selector(isBlack), @selector(kn_isBlack));

        // 3. TuringShield 指纹 (定向 hook)
        Class turingCls = objc_getClass("TuringShieldUNBC");
        if (turingCls) {
            kn_swizzle(turingCls,
                @selector(getFingerprintOnlineWithCompletionHandler:),
                @selector(kn_getFingerprintOnlineWithCompletionHandler:));
        }

        // blockedFingerprintConfig (只 hook GDTExpRule)
        Class gdt = objc_getClass("GDTExpRule");
        if (gdt) {
            kn_swizzle(gdt, @selector(blockedFingerprintConfig), @selector(kn_blockedFingerprintConfig));
            kn_swizzle(gdt, @selector(setBlockedFingerprintConfig:), @selector(kn_setBlockedFingerprintConfig:));
        }

        // 4. OpenUDID 随机化 (定向 hook)
        Class umUtils = objc_getClass("UMUtils");
        if (umUtils) {
            kn_swizzleClass(umUtils, @selector(openUDIDString), @selector(kn_openUDIDString));
        }
        Class openUDIDCls = objc_getClass("OpenUDID");
        if (openUDIDCls) {
            kn_swizzleClass(openUDIDCls, @selector(value), @selector(kn_openUDIDString));
        }
        Class iflyUDID = objc_getClass("IFlyOpenUDID");
        if (iflyUDID) {
            kn_swizzleClass(iflyUDID, @selector(openUDIDString), @selector(kn_openUDIDString));
        }

        // 5. 越狱检测 (app 自定义 selector)
        hookAppClassesWithSelector(@selector(isDeviceJailBreak), @selector(kn_isDeviceJailBreak));
        hookAppClassesWithSelector(@selector(getDeviceJailBreakString), @selector(kn_getDeviceJailBreakString));
        hookAppClassesWithSelector(@selector(deviceJailBreakString), @selector(kn_deviceJailBreakString));

        // GDT 越狱检测 (定向)
        Class gdtDevMgr = objc_getClass("GDTDeviceManager");
        if (gdtDevMgr) {
            kn_swizzle(gdtDevMgr, @selector(isJailBroken), @selector(kn_isJailBroken));
        }

        // stee_isJailbreak
        NSArray *steeSelNames = @[
            @"stee_isJailbreak_1", @"stee_isJailbreak_2", @"stee_isJailbreak_3",
            @"stee_isJailbreak_4", @"stee_isJailbreak_5", @"stee_isJailbreak_6",
            @"stee_isJailbreak_7"
        ];
        for (NSString *selName in steeSelNames) {
            hookAppClassesWithSelector(NSSelectorFromString(selName), @selector(kn_stee_isJailbreak_stub));
        }

        // 6. WPK 调试检测
        Class wpkClass = objc_getClass("WPKOOMDetector");
        if (wpkClass) {
            kn_swizzleClass(wpkClass, @selector(isBeingDebugged), @selector(kn_isBeingDebugged));
        }

        // 7. 签名检测
        hookAppClassesWithSelector(@selector(checkSignAuthIfNeed:), @selector(kn_checkSignAuthIfNeed:));
        hookAppClassesWithSelector(@selector(initFilterConfigAndVerify), @selector(kn_initFilterConfigAndVerify));
        hookAppClassesWithSelector(@selector(processSaveAppSignInfo:), @selector(kn_processSaveAppSignInfo:));

        // 8. PiP
        Class avPipCls = objc_getClass("AVPictureInPictureController");
        if (avPipCls) {
            kn_swizzleClass(avPipCls, @selector(isPictureInPictureSupported), @selector(kn_isPictureInPictureSupported));
        }

        // 9. 播放器 PiP hook
        NSArray *playerClassNames = @[@"SJBaseVideoPlayer", @"SJVideoPlayer", @"AliPlayer"];
        for (NSString *name in playerClassNames) {
            Class cls = objc_getClass(name.UTF8String);
            if (cls && class_getInstanceMethod(cls, @selector(setPlayerView:))) {
                kn_swizzle(cls, @selector(setPlayerView:), @selector(kn_sj_setPlayerView:));
            }
        }

        // 10. 直播页 PiP 按钮
        Class liveCls = objc_getClass("LiveDetailController");
        if (liveCls) {
            kn_swizzle(liveCls, @selector(viewDidAppear:), @selector(kn_live_viewDidAppear:));
        }

        // 11. fishhook: 路径检测 (只 hook access，不 hook stat 避免 iOS 14 崩溃)
        struct rebinding rb = {"access", (void *)kn_access, (void **)&orig_access};
        rebind_symbols(&rb, 1);

        NSLog(@"[KN] v2.2 hooks installed OK");

    } @catch (NSException *e) {
        NSLog(@"[KN] Setup exception: %@", e);
    }
}

__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        kn_setup();
    });
}
