// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (精简版)
// 兼容: iOS 14+ / 巨魔注入 / 轻松签注入
// v3.0 — 去掉 PiP、去掉全局遍历、去掉 fishhook，纯定向 hook

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - 安全 swizzle 工具

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

#pragma mark - 随机设备 ID

static NSString *kn_fakeUDID(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    NSString *key = @"kn_fake_udid";
    cached = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (!cached || cached.length == 0) {
        cached = [[NSUUID UUID] UUIDString];
        [[NSUserDefaults standardUserDefaults] setObject:cached forKey:key];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    return cached;
}

#pragma mark - NSURLProtocol 拦截 checkDeviceStatus

@interface KNDeviceProtocol : NSURLProtocol
@end

@implementation KNDeviceProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([request.URL.absoluteString containsString:@"checkDeviceStatus"]) {
        if ([NSURLProtocol propertyForKey:@"KN" inRequest:request]) return NO;
        return YES;
    }
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSDictionary *fake = @{
        @"code": @200, @"msg": @"success",
        @"data": @{@"isBlack": @0, @"is_black": @0, @"status": @1,
                    @"deviceStatus": @1, @"banned": @0, @"isBanned": @0, @"black": @0}
    };
    NSData *body = [NSJSONSerialization dataWithJSONObject:fake options:0 error:nil];
    NSHTTPURLResponse *resp = [[NSHTTPURLResponse alloc]
        initWithURL:self.request.URL statusCode:200
        HTTPVersion:@"HTTP/1.1"
        headerFields:@{@"Content-Type": @"application/json"}];
    NSMutableURLRequest *mr = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"KN" inRequest:mr];
    [self.client URLProtocol:self didReceiveResponse:resp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:body];
    [self.client URLProtocolDidFinishLoading:self];
}

- (void)stopLoading {}

@end

#pragma mark - Hook 实现 (全部挂在 NSObject category 上)

@interface NSObject (KNBypass)
// isBlack
- (void)kn_setIsBlack:(BOOL)v;
- (BOOL)kn_isBlack;
// 越狱
- (BOOL)kn_isDeviceJailBreak;
- (NSString *)kn_getDeviceJailBreakString;
- (NSString *)kn_deviceJailBreakString;
- (BOOL)kn_stee_jb_stub;
- (BOOL)kn_isJailBroken;
// 签名
- (void)kn_checkSignAuthIfNeed:(id)a;
- (void)kn_initFilterConfigAndVerify;
- (void)kn_processSaveAppSignInfo:(id)a;
// TuringShield
- (void)kn_getFP:(id)handler;
- (NSDictionary *)kn_blockedFPConfig;
- (void)kn_setBlockedFPConfig:(NSDictionary *)c;
// OpenUDID
+ (NSString *)kn_openUDIDString;
// WPK
+ (BOOL)kn_isBeingDebugged;
@end

@implementation NSObject (KNBypass)
- (void)kn_setIsBlack:(BOOL)v { [self kn_setIsBlack:NO]; }
- (BOOL)kn_isBlack { return NO; }
- (BOOL)kn_isDeviceJailBreak { return NO; }
- (NSString *)kn_getDeviceJailBreakString { return @""; }
- (NSString *)kn_deviceJailBreakString { return @""; }
- (BOOL)kn_stee_jb_stub { return NO; }
- (BOOL)kn_isJailBroken { return NO; }
- (void)kn_checkSignAuthIfNeed:(id)a {}
- (void)kn_initFilterConfigAndVerify {}
- (void)kn_processSaveAppSignInfo:(id)a {}
- (void)kn_getFP:(id)handler {
    if (handler) { void(^blk)(id) = handler; blk(nil); }
}
- (NSDictionary *)kn_blockedFPConfig { return @{}; }
- (void)kn_setBlockedFPConfig:(NSDictionary *)c { [self kn_setBlockedFPConfig:@{}]; }
+ (NSString *)kn_openUDIDString { return kn_fakeUDID(); }
+ (BOOL)kn_isBeingDebugged { return NO; }
@end

#pragma mark - 定向 hook 指定类名 + selector

typedef struct {
    const char *className;
    SEL origSel;
    SEL newSel;
    BOOL isClassMethod;
} KNHookEntry;

static void kn_installHooks(KNHookEntry *entries, int count) {
    for (int i = 0; i < count; i++) {
        Class cls = objc_getClass(entries[i].className);
        if (!cls) continue;
        if (entries[i].isClassMethod) {
            kn_swizzleClass(cls, entries[i].origSel, entries[i].newSel);
        } else {
            kn_swizzle(cls, entries[i].origSel, entries[i].newSel);
        }
    }
}

#pragma mark - 入口

static void kn_setup(void) {
    @try {
        // 1. 网络拦截
        [NSURLProtocol registerClass:[KNDeviceProtocol class]];

        // 2. 定向 hook 表
        // 从二进制 strings 确认的类名和 selector
        KNHookEntry hooks[] = {
            // TuringShield 指纹
            {"TuringShieldUNBC", @selector(getFingerprintOnlineWithCompletionHandler:), @selector(kn_getFP:), NO},
            // 封禁指纹配置
            {"GDTExpRule", @selector(blockedFingerprintConfig), @selector(kn_blockedFPConfig), NO},
            {"GDTExpRule", @selector(setBlockedFingerprintConfig:), @selector(kn_setBlockedFPConfig:), NO},
            // OpenUDID
            {"UMUtils", @selector(openUDIDString), @selector(kn_openUDIDString), YES},
            {"OpenUDID", @selector(value), @selector(kn_openUDIDString), YES},
            {"IFlyOpenUDID", @selector(openUDIDString), @selector(kn_openUDIDString), YES},
            // GDT 越狱检测
            {"GDTDeviceManager", @selector(isJailBroken), @selector(kn_isJailBroken), NO},
            // WPK 调试检测
            {"WPKOOMDetector", @selector(isBeingDebugged), @selector(kn_isBeingDebugged), YES},
            // 签名检测 — MAGAPP 框架类
            {"MAGAppDelegate", @selector(checkSignAuthIfNeed:), @selector(kn_checkSignAuthIfNeed:), NO},
            {"MAGAppDelegate", @selector(initFilterConfigAndVerify), @selector(kn_initFilterConfigAndVerify), NO},
            {"MAGAppDelegate", @selector(processSaveAppSignInfo:), @selector(kn_processSaveAppSignInfo:), NO},
            // 越狱检测 — MAGAPP 框架类
            {"MAGAppDelegate", @selector(isDeviceJailBreak), @selector(kn_isDeviceJailBreak), NO},
            {"MAGAppDelegate", @selector(getDeviceJailBreakString), @selector(kn_getDeviceJailBreakString), NO},
            {"MAGAppDelegate", @selector(deviceJailBreakString), @selector(kn_deviceJailBreakString), NO},
        };
        kn_installHooks(hooks, sizeof(hooks) / sizeof(hooks[0]));

        // 3. stee_isJailbreak_1..7 (只 hook 有这些方法的 MAGAPP 类)
        NSArray *steeClasses = @[@"MAGAppDelegate", @"MAGNetworkManager", @"MAGUserManager"];
        for (NSString *clsName in steeClasses) {
            Class cls = objc_getClass(clsName.UTF8String);
            if (!cls) continue;
            for (int j = 1; j <= 7; j++) {
                NSString *selName = [NSString stringWithFormat:@"stee_isJailbreak_%d", j];
                SEL sel = NSSelectorFromString(selName);
                if (class_getInstanceMethod(cls, sel)) {
                    kn_swizzle(cls, sel, @selector(kn_stee_jb_stub));
                }
            }
        }

        // 4. isBlack — 只 hook 可能的模型类
        NSArray *blackClasses = @[@"MAGUserModel", @"MAGDeviceModel", @"MAGConfigModel",
                                   @"UserModel", @"DeviceModel", @"ConfigModel"];
        for (NSString *clsName in blackClasses) {
            Class cls = objc_getClass(clsName.UTF8String);
            if (!cls) continue;
            if (class_getInstanceMethod(cls, @selector(isBlack))) {
                kn_swizzle(cls, @selector(isBlack), @selector(kn_isBlack));
            }
            if (class_getInstanceMethod(cls, @selector(setIsBlack:))) {
                kn_swizzle(cls, @selector(setIsBlack:), @selector(kn_setIsBlack:));
            }
        }

        NSLog(@"[KN] v3.0 all hooks installed");

    } @catch (NSException *e) {
        NSLog(@"[KN] exception: %@", e);
    }
}

__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        kn_setup();
    });
}
