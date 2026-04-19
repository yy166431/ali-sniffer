// AliSniffer.m - 酷牛 v6.4.1 设备黑名单/指纹/签名/越狱检测 Bypass + PiP 画中画
// 注入方式: 轻松签/巨魔 dylib 注入 (非越狱)
// 更新: 2026-04 v2.1 — 修复闪退，精确定向 hook

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVKit/AVKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <sys/stat.h>
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

// 安全地给指定类添加并交换实例方法
static void kn_safeSwizzleInstance(Class targetCls, SEL origSel, SEL newSel, Class implCls) {
    if (!targetCls) return;
    Method origMethod = class_getInstanceMethod(targetCls, origSel);
    if (!origMethod) return;
    Method newMethod = class_getInstanceMethod(implCls, newSel);
    if (!newMethod) return;
    // 先尝试添加，防止 hook 父类方法
    BOOL added = class_addMethod(targetCls, origSel,
        method_getImplementation(newMethod), method_getTypeEncoding(newMethod));
    if (added) {
        class_replaceMethod(targetCls, newSel,
            method_getImplementation(origMethod), method_getTypeEncoding(origMethod));
    } else {
        method_exchangeImplementations(origMethod, newMethod);
    }
}

// 遍历所有类，对含有指定方法的类批量 hook (仅用于 app 自身的 selector)
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

    NSString *key = @"kn_random_udid_v2";
    NSString *stored = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (stored.length > 0) {
        cachedID = stored;
        return cachedID;
    }

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
    if (@available(iOS 13.0, *)) {
        [btn setImage:[UIImage systemImageNamed:@"pip.enter"] forState:UIControlStateNormal];
    } else {
        [btn setTitle:@"PiP" forState:UIControlStateNormal];
    }
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
                    id pipPlayer = ((id (*)(id, SEL))objc_msgSend)(val, @selector(pipPlayer));
                    if (pipPlayer && [pipPlayer respondsToSelector:@selector(startPictureInPicture)]) {
                        ((void (*)(id, SEL))objc_msgSend)(pipPlayer, @selector(startPictureInPicture));
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

#pragma mark - TuringShield 指纹 Bypass (定向 hook，不遍历全局)

// 用 IMP 替换方式，避免 swizzle 类型不匹配崩溃
static void kn_hookTuringShield(void) {
    // 1. TuringShieldUNBC getFingerprintOnlineWithCompletionHandler:
    Class turingCls = objc_getClass("TuringShieldUNBC");
    if (turingCls) {
        SEL sel = @selector(getFingerprintOnlineWithCompletionHandler:);
        Method m = class_getInstanceMethod(turingCls, sel);
        if (m) {
            IMP newIMP = imp_implementationWithBlock(^(id self, void(^handler)(id)) {
                NSLog(@"[KN] TuringShield fingerprint intercepted");
                if (handler) handler(nil);
            });
            method_setImplementation(m, newIMP);
        }
    }

    // 2. blockedFingerprintConfig getter → 返回空字典
    //    只 hook 含有此属性的 GDT 相关类，不全局遍历
    NSArray *fpClasses = @[@"GDTExpRule", @"GDTAdBaseModel"];
    for (NSString *name in fpClasses) {
        Class cls = objc_getClass(name.UTF8String);
        if (!cls) continue;
        SEL getSel = @selector(blockedFingerprintConfig);
        Method getM = class_getInstanceMethod(cls, getSel);
        if (getM) {
            IMP newGet = imp_implementationWithBlock(^NSDictionary *(id self) {
                return @{};
            });
            method_setImplementation(getM, newGet);
        }
        SEL setSel = @selector(setBlockedFingerprintConfig:);
        Method setM = class_getInstanceMethod(cls, setSel);
        if (setM) {
            IMP newSet = imp_implementationWithBlock(^(id self, NSDictionary *cfg) {
                // 丢弃封禁配置
            });
            method_setImplementation(setM, newSet);
        }
    }
}

#pragma mark - OpenUDID Bypass (定向 hook)

static void kn_hookOpenUDID(void) {
    // UMUtils +openUDIDString
    Class umUtils = objc_getClass("UMUtils");
    if (umUtils) {
        SEL sel = @selector(openUDIDString);
        Method m = class_getClassMethod(umUtils, sel);
        if (m) {
            IMP newIMP = imp_implementationWithBlock(^NSString *(id self) {
                return kn_persistentRandomUDID();
            });
            method_setImplementation(m, newIMP);
            NSLog(@"[KN] UMUtils.openUDIDString hooked");
        }
    }

    // OpenUDID +value / +openUDIDString
    Class openUDIDCls = objc_getClass("OpenUDID");
    if (openUDIDCls) {
        IMP fakeIMP = imp_implementationWithBlock(^NSString *(id self) {
            return kn_persistentRandomUDID();
        });
        SEL selArr[] = { @selector(value), @selector(openUDIDString) };
        for (int i = 0; i < 2; i++) {
            Method m = class_getClassMethod(openUDIDCls, selArr[i]);
            if (m) {
                method_setImplementation(m, fakeIMP);
            }
        }
        NSLog(@"[KN] OpenUDID class hooked");
    }

    // IFlyOpenUDID (讯飞)
    Class iflyUDID = objc_getClass("IFlyOpenUDID");
    if (iflyUDID) {
        SEL sel = @selector(openUDIDString);
        Method m = class_getClassMethod(iflyUDID, sel);
        if (m) {
            IMP newIMP = imp_implementationWithBlock(^NSString *(id self) {
                return kn_persistentRandomUDID();
            });
            method_setImplementation(m, newIMP);
        }
    }
}

#pragma mark - GDT 越狱检测 (定向 hook)

static void kn_hookGDTJailbreak(void) {
    Class gdtDevMgr = objc_getClass("GDTDeviceManager");
    if (!gdtDevMgr) return;

    SEL sel = @selector(isJailBroken);
    Method m = class_getInstanceMethod(gdtDevMgr, sel);
    if (m) {
        IMP newIMP = imp_implementationWithBlock(^BOOL(id self) {
            return NO;
        });
        method_setImplementation(m, newIMP);
        NSLog(@"[KN] GDTDeviceManager.isJailBroken hooked");
    }
}

#pragma mark - fishhook: 文件存在性检查 bypass (巨魔路径)

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
    NSLog(@"[KN] === KNBypass v2.1 Setup Start ===");

    // 1. 注册网络拦截
    [NSURLProtocol registerClass:[KNDeviceStatusProtocol class]];

    // 2. 遍历 hook setIsBlack: / isBlack (这两个是 app 自定义的，安全)
    hookAllClassesWithSelector(
        @selector(setIsBlack:), @selector(kn_setIsBlack:), NO);
    hookAllClassesWithSelector(
        @selector(isBlack), @selector(kn_isBlack), NO);

    // 3. TuringShield 指纹 bypass (定向 IMP 替换)
    kn_hookTuringShield();

    // 4. OpenUDID 随机化 (定向 IMP 替换)
    kn_hookOpenUDID();

    // 5. 越狱检测 (仅 hook app 自定义的 selector)
    hookAllClassesWithSelector(
        @selector(isDeviceJailBreak), @selector(kn_isDeviceJailBreak), NO);
    hookAllClassesWithSelector(
        @selector(getDeviceJailBreakString), @selector(kn_getDeviceJailBreakString), NO);
    hookAllClassesWithSelector(
        @selector(deviceJailBreakString), @selector(kn_deviceJailBreakString), NO);

    // GDT 越狱检测 (定向 IMP 替换，不全局遍历)
    kn_hookGDTJailbreak();

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

    // 6. WPK 调试检测 (定向)
    Class wpkClass = objc_getClass("WPKOOMDetector");
    if (wpkClass) {
        KN_SWIZZLE_CLASS(wpkClass,
            @selector(isBeingDebugged),
            @selector(kn_isBeingDebugged));
    }

    // 7. 签名检测
    hookAllClassesWithSelector(
        @selector(checkSignAuthIfNeed:), @selector(kn_checkSignAuthIfNeed:), NO);
    hookAllClassesWithSelector(
        @selector(initFilterConfigAndVerify), @selector(kn_initFilterConfigAndVerify), NO);
    hookAllClassesWithSelector(
        @selector(processSaveAppSignInfo:), @selector(kn_processSaveAppSignInfo:), NO);

    // 8. PiP — AVPictureInPictureController
    Class avPipCls = objc_getClass("AVPictureInPictureController");
    if (avPipCls) {
        KN_SWIZZLE_CLASS(avPipCls,
            @selector(isPictureInPictureSupported),
            @selector(kn_isPictureInPictureSupported));
    }

    // 9. PiP — SJVideoPlayer / SJBaseVideoPlayer / AliPlayer
    NSArray *playerClassNames = @[@"SJBaseVideoPlayer", @"SJVideoPlayer", @"AliPlayer"];
    for (NSString *name in playerClassNames) {
        Class cls = objc_getClass(name.UTF8String);
        if (!cls) continue;
        Method m = class_getInstanceMethod(cls, @selector(setPlayerView:));
        if (m) {
            KN_SWIZZLE_INSTANCE(cls,
                @selector(setPlayerView:),
                @selector(kn_sj_setPlayerView:));
        }
    }

    // 10. 直播页 PiP 按钮
    Class liveCls = objc_getClass("LiveDetailController");
    if (liveCls) {
        KN_SWIZZLE_INSTANCE(liveCls,
            @selector(viewDidAppear:),
            @selector(kn_live_viewDidAppear:));
    }

    // 11. fishhook: 越狱/巨魔路径检测 bypass
    struct rebinding rebindings[] = {
        {"access", (void *)kn_access, (void **)&orig_access},
        {"stat", (void *)kn_stat, (void **)&orig_stat},
    };
    rebind_symbols(rebindings, 2);

    NSLog(@"[KN] === KNBypass v2.1 Setup Complete ===");
}

__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        kn_setup();
    });
}
