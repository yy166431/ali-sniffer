// AliSniffer.m - 酷牛 v6.4.1 设备黑名单/指纹/签名/越狱检测 Bypass + PiP 画中画
// 注入方式: 轻松签/巨魔 dylib 注入 (非越狱)
// 更新: 2026-04 — 适配 TuringShield 指纹封禁 + SJVideoPlayer PiP

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

#pragma mark - 随机设备 ID 生成 (每次安装后固定，重装变化)

static NSString *kn_persistentRandomUDID(void) {
    static NSString *cachedID = nil;
    if (cachedID) return cachedID;

    // 存在 NSUserDefaults 里，删 APP 就重置
    NSString *key = @"kn_random_udid_v2";
    NSString *stored = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (stored.length > 0) {
        cachedID = stored;
        return cachedID;
    }

    // 生成随机 UUID
    cachedID = [[NSUUID UUID] UUIDString];
    [[NSUserDefaults standardUserDefaults] setObject:cachedID forKey:key];
    [[NSUserDefaults standardUserDefaults] synchronize];
    NSLog(@"[KN] Generated new random UDID: %@", cachedID);
    return cachedID;
}

#pragma mark - NSURLProtocol 拦截 checkDeviceStatus

@interface KNDeviceStatusProtocol : NSURLProtocol
@end

@implementation KNDeviceStatusProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *url = request.URL.absoluteString;
    // 拦截设备状态检查
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
            @"is_forbidden": @0,
            @"isForbidden": @0,
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
    NSLog(@"[KN] Intercepted checkDeviceStatus → fake OK");
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

#pragma mark - TuringShield 指纹 Bypass

@interface NSObject (KNTuringBypass)
- (void)kn_getFingerprintOnlineWithCompletionHandler:(void(^)(id fp))handler;
- (NSDictionary *)kn_blockedFingerprintConfig;
- (void)kn_setBlockedFingerprintConfig:(NSDictionary *)config;
@end

@implementation NSObject (KNTuringBypass)

// TuringShieldUNBC getFingerprintOnlineWithCompletionHandler: → 返回空/假指纹
- (void)kn_getFingerprintOnlineWithCompletionHandler:(void(^)(id fp))handler {
    NSLog(@"[KN] TuringShield fingerprint request intercepted, returning nil");
    if (handler) {
        handler(nil);
    }
}

// blockedFingerprintConfig → 返回空字典，不封任何指纹
- (NSDictionary *)kn_blockedFingerprintConfig {
    return @{};
}

- (void)kn_setBlockedFingerprintConfig:(NSDictionary *)config {
    // 忽略服务端下发的封禁指纹配置
    [self kn_setBlockedFingerprintConfig:@{}];
    NSLog(@"[KN] Blocked fingerprint config suppressed");
}

@end

#pragma mark - OpenUDID Bypass (随机化设备 ID)

@interface NSObject (KNOpenUDIDBypass)
+ (NSString *)kn_openUDIDString;
@end

@implementation NSObject (KNOpenUDIDBypass)

+ (NSString *)kn_openUDIDString {
    NSString *fakeID = kn_persistentRandomUDID();
    NSLog(@"[KN] OpenUDID spoofed: %@", fakeID);
    return fakeID;
}

@end

#pragma mark - 越狱检测 Bypass

@interface NSObject (KNJailbreakBypass)
- (BOOL)kn_isDeviceJailBreak;
- (NSString *)kn_getDeviceJailBreakString;
- (NSString *)kn_deviceJailBreakString;
- (BOOL)kn_isJailBroken;
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

- (BOOL)kn_isJailBroken {
    return NO;
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
- (BOOL)kn_isDebugging;
@end

@implementation NSObject (KNDebugBypass)
+ (BOOL)kn_isBeingDebugged { return NO; }
- (BOOL)kn_isDebugging { return NO; }
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

#pragma mark - PiP 画中画 (SJVideoPlayer)

// 绕过系统对 UIBackgroundModes 的检查
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

// SJVideoPlayer / SJBaseVideoPlayer 的 playbackController 设置时自动开启 PiP
- (void)kn_sj_setPlayerView:(UIView *)view {
    [self kn_sj_setPlayerView:view];
    // 尝试通过 SJBaseVideoPlayer 的 PiP 接口开启
    if ([self respondsToSelector:@selector(setPictureInPictureEnable:)]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(self, @selector(setPictureInPictureEnable:), YES);
        NSLog(@"[KN] SJVideoPlayer PiP enabled via setPlayerView");
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
    [btn addTarget:self action:@selector(kn_triggerSJPiP) forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:btn];
    NSLog(@"[KN] PiP button injected into LiveDetailController");
}

// 点击按钮：遍历 ivar 找 SJBaseVideoPlayer / SJVideoPlayer 实例并触发 PiP
- (void)kn_triggerSJPiP {
    // 尝试多个播放器类名
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
                    NSLog(@"[KN] PiP triggered on %@", clsName);
                }
                // SJBaseVideoPlayer 可能有 pipPlayer 属性
                if ([val respondsToSelector:@selector(pipPlayer)]) {
                    id pipPlayer = ((id (*)(id, SEL))objc_msgSend)(val, @selector(pipPlayer));
                    if (pipPlayer && [pipPlayer respondsToSelector:@selector(startPictureInPicture)]) {
                        ((void (*)(id, SEL))objc_msgSend)(pipPlayer, @selector(startPictureInPicture));
                        NSLog(@"[KN] PiP started via pipPlayer");
                    }
                }
                free(ivars);
                return;
            }
        }
        free(ivars);
    }
    NSLog(@"[KN] No player instance found for PiP");
}

@end

#pragma mark - fishhook: 文件存在性检查 bypass (越狱路径)

static int (*orig_access)(const char *, int);
static int kn_access(const char *path, int mode) {
    if (path) {
        NSString *p = [NSString stringWithUTF8String:path];
        NSArray *blocked = @[
            @"/Applications/Cydia.app",
            @"/Library/MobileSubstrate",
            @"/usr/sbin/sshd",
            @"/etc/apt",
            @"/bin/bash",
            @"/usr/bin/ssh",
            @"/var/jb",
            @"/var/containers/Bundle/tweaksupport",
        ];
        for (NSString *b in blocked) {
            if ([p hasPrefix:b]) return -1;
        }
    }
    return orig_access(path, mode);
}

static int (*orig_stat)(const char *, struct stat *);
static int kn_stat(const char *path, struct stat *buf) {
    if (path) {
        NSString *p = [NSString stringWithUTF8String:path];
        if ([p containsString:@"Cydia"] ||
            [p containsString:@"MobileSubstrate"] ||
            [p containsString:@"sshd"] ||
            [p containsString:@"/var/jb"]) {
            return -1;
        }
    }
    return orig_stat(path, buf);
}

#pragma mark - 初始化入口

static void kn_setup(void) {
    NSLog(@"[KN] === KNBypass v2.0 Setup Start ===");

    // 1. 注册网络拦截
    [NSURLProtocol registerClass:[KNDeviceStatusProtocol class]];
    NSLog(@"[KN] NSURLProtocol registered for checkDeviceStatus");

    // 2. 遍历 hook setIsBlack: / isBlack
    hookAllClassesWithSelector(
        @selector(setIsBlack:), @selector(kn_setIsBlack:), NO);
    hookAllClassesWithSelector(
        @selector(isBlack), @selector(kn_isBlack), NO);
    NSLog(@"[KN] isBlack hooks installed");

    // 3. TuringShield 指纹 bypass
    Class turingCls = objc_getClass("TuringShieldUNBC");
    if (turingCls) {
        KN_SWIZZLE_INSTANCE(turingCls,
            @selector(getFingerprintOnlineWithCompletionHandler:),
            @selector(kn_getFingerprintOnlineWithCompletionHandler:));
        NSLog(@"[KN] TuringShield fingerprint hook installed");
    }

    // blockedFingerprintConfig — hook 所有含此属性的类
    hookAllClassesWithSelector(
        @selector(blockedFingerprintConfig),
        @selector(kn_blockedFingerprintConfig), NO);
    hookAllClassesWithSelector(
        @selector(setBlockedFingerprintConfig:),
        @selector(kn_setBlockedFingerprintConfig:), NO);
    NSLog(@"[KN] blockedFingerprintConfig hooks installed");

    // 4. OpenUDID 随机化
    Class umUtils = objc_getClass("UMUtils");
    if (umUtils) {
        KN_SWIZZLE_CLASS(umUtils,
            @selector(openUDIDString),
            @selector(kn_openUDIDString));
        NSLog(@"[KN] OpenUDID (UMUtils) hook installed");
    }
    // 也 hook OpenUDID 类本身
    Class openUDIDCls = objc_getClass("OpenUDID");
    if (openUDIDCls) {
        Method m = class_getClassMethod(openUDIDCls, @selector(value));
        if (m) {
            KN_SWIZZLE_CLASS(openUDIDCls, @selector(value), @selector(kn_openUDIDString));
        }
        Method m2 = class_getClassMethod(openUDIDCls, @selector(openUDIDString));
        if (m2) {
            KN_SWIZZLE_CLASS(openUDIDCls, @selector(openUDIDString), @selector(kn_openUDIDString));
        }
        NSLog(@"[KN] OpenUDID class hook installed");
    }

    // 5. 越狱检测
    hookAllClassesWithSelector(
        @selector(isDeviceJailBreak), @selector(kn_isDeviceJailBreak), NO);
    hookAllClassesWithSelector(
        @selector(getDeviceJailBreakString), @selector(kn_getDeviceJailBreakString), NO);
    hookAllClassesWithSelector(
        @selector(deviceJailBreakString), @selector(kn_deviceJailBreakString), NO);
    hookAllClassesWithSelector(
        @selector(isJailBroken), @selector(kn_isJailBroken), NO);

    // GDTDeviceManager isJailBroken
    Class gdtDevMgr = objc_getClass("GDTDeviceManager");
    if (gdtDevMgr) {
        KN_SWIZZLE_INSTANCE(gdtDevMgr,
            @selector(isJailBroken), @selector(kn_isJailBroken));
    }

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
    NSLog(@"[KN] Jailbreak detection hooks installed");

    // 6. WPK 调试检测
    Class wpkClass = objc_getClass("WPKOOMDetector");
    if (wpkClass) {
        KN_SWIZZLE_CLASS(wpkClass,
            @selector(isBeingDebugged),
            @selector(kn_isBeingDebugged));
    }
    hookAllClassesWithSelector(
        @selector(isDebugging), @selector(kn_isDebugging), NO);
    NSLog(@"[KN] Debug detection hooks installed");

    // 7. 签名检测
    hookAllClassesWithSelector(
        @selector(checkSignAuthIfNeed:), @selector(kn_checkSignAuthIfNeed:), NO);
    hookAllClassesWithSelector(
        @selector(initFilterConfigAndVerify), @selector(kn_initFilterConfigAndVerify), NO);
    hookAllClassesWithSelector(
        @selector(processSaveAppSignInfo:), @selector(kn_processSaveAppSignInfo:), NO);
    NSLog(@"[KN] Signature detection hooks installed");

    // 8. PiP — AVPictureInPictureController
    Class avPipCls = objc_getClass("AVPictureInPictureController");
    if (avPipCls) {
        KN_SWIZZLE_CLASS(avPipCls,
            @selector(isPictureInPictureSupported),
            @selector(kn_isPictureInPictureSupported));
    }

    // 9. PiP — SJVideoPlayer / SJBaseVideoPlayer
    NSArray *sjClassNames = @[@"SJBaseVideoPlayer", @"SJVideoPlayer"];
    for (NSString *name in sjClassNames) {
        Class sjCls = objc_getClass(name.UTF8String);
        if (sjCls) {
            Method m = class_getInstanceMethod(sjCls, @selector(setPlayerView:));
            if (m) {
                KN_SWIZZLE_INSTANCE(sjCls,
                    @selector(setPlayerView:),
                    @selector(kn_sj_setPlayerView:));
                NSLog(@"[KN] %@ setPlayerView: PiP hook installed", name);
            }
        }
    }

    // 也保留 AliPlayer hook 以防万一
    Class aliCls = objc_getClass("AliPlayer");
    if (aliCls) {
        Method m = class_getInstanceMethod(aliCls, @selector(setPlayerView:));
        if (m) {
            KN_SWIZZLE_INSTANCE(aliCls,
                @selector(setPlayerView:),
                @selector(kn_sj_setPlayerView:));
            NSLog(@"[KN] AliPlayer setPlayerView: PiP hook installed");
        }
    }

    // 10. 直播页 PiP 按钮
    Class liveCls = objc_getClass("LiveDetailController");
    if (liveCls) {
        KN_SWIZZLE_INSTANCE(liveCls,
            @selector(viewDidAppear:),
            @selector(kn_live_viewDidAppear:));
        NSLog(@"[KN] LiveDetailController PiP button hook installed");
    }

    // 11. fishhook: 越狱路径检测 bypass
    rebind_symbols((struct rebinding[2]){
        {"access", kn_access, (void *)&orig_access},
        {"stat", kn_stat, (void *)&orig_stat},
    }, 2);
    NSLog(@"[KN] fishhook access/stat bypass installed");

    NSLog(@"[KN] === KNBypass v2.0 Setup Complete ===");
}

// dylib 加载时自动执行
__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        kn_setup();
    });
}
