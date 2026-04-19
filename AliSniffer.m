// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (精简版 v3.1)
// 兼容: iOS 14+ / 巨魔注入 / 轻松签注入
// 核心: 拦截 checkDeviceStatus + 清除友盟本地黑名单 + 随机化设备ID

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - 安全 swizzle

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

#pragma mark - 清除友盟本地黑名单缓存

static void kn_clearUMengFilterCache(void) {
    // 友盟 filter 数据存在 Library 目录下
    NSArray *paths = @[
        @"Library/Caches",
        @"Library/Preferences",
        @"Documents",
        @"Library",
    ];
    NSString *home = NSHomeDirectory();
    NSFileManager *fm = [NSFileManager defaultManager];

    for (NSString *sub in paths) {
        NSString *dir = [home stringByAppendingPathComponent:sub];
        NSArray *files = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *file in files) {
            // 删除友盟 filter/imprint 相关文件
            NSString *lower = [file lowercaseString];
            if ([lower containsString:@"umeng"] ||
                [lower containsString:@"umfilter"] ||
                [lower containsString:@"umimprint"] ||
                [lower containsString:@"umcom"] ||
                [lower containsString:@"blackfilter"] ||
                [lower containsString:@"filterconfig"] ||
                [lower containsString:@"filterlist"]) {
                NSString *full = [dir stringByAppendingPathComponent:file];
                [fm removeItemAtPath:full error:nil];
                NSLog(@"[KN] Removed filter cache: %@", file);
            }
        }
    }

    // 清除 NSUserDefaults 中友盟相关的 key
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [ud dictionaryRepresentation];
    for (NSString *key in all) {
        NSString *lower = [key lowercaseString];
        if ([lower containsString:@"umeng"] ||
            [lower containsString:@"umfilter"] ||
            [lower containsString:@"umimprint"] ||
            [lower containsString:@"blackfilter"] ||
            [lower containsString:@"filterconfig"] ||
            [lower containsString:@"openudid"] ||
            [lower containsString:@"turing"]) {
            [ud removeObjectForKey:key];
            NSLog(@"[KN] Removed UD key: %@", key);
        }
    }
    [ud synchronize];
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

#pragma mark - Hook 实现

@interface NSObject (KNBypass)
// isBlack 模型
- (void)kn_setIsBlack:(BOOL)v;
- (BOOL)kn_isBlack;
// 友盟黑名单 filter
- (BOOL)kn_doIsBlackFilterValue:(id)value withFilterType:(NSInteger)type;
- (BOOL)kn_isBlackDomainUrl:(id)url;
- (BOOL)kn_isFilterValueForBlackFilter:(id)value;
- (BOOL)kn_verifyFilterValue:(id)v1 withImprintMD5Value:(id)v2 withUserdefaultMD5Vlaue:(id)v3;
- (id)kn_createBlackFilterWithSerialize:(id)data;
- (void)kn_doAddFilterValueForBlackFilter:(id)value;
- (id)kn_doProcessSerializeForBlackFilter:(id)data;
- (void)kn_writeFilterListValue:(id)value withFilterType:(NSInteger)type;
- (void)kn_initFilterConfigAndVerify;
// 越狱
- (BOOL)kn_isDeviceJailBreak;
- (NSString *)kn_getDeviceJailBreakString;
- (NSString *)kn_deviceJailBreakString;
- (BOOL)kn_stee_jb_stub;
- (BOOL)kn_isJailBroken;
// 签名
- (void)kn_checkSignAuthIfNeed:(id)a;
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

// isBlack
- (void)kn_setIsBlack:(BOOL)v { [self kn_setIsBlack:NO]; }
- (BOOL)kn_isBlack { return NO; }

// 友盟黑名单 — 全部返回"不在黑名单"
- (BOOL)kn_doIsBlackFilterValue:(id)value withFilterType:(NSInteger)type { return NO; }
- (BOOL)kn_isBlackDomainUrl:(id)url { return NO; }
- (BOOL)kn_isFilterValueForBlackFilter:(id)value { return NO; }
- (BOOL)kn_verifyFilterValue:(id)v1 withImprintMD5Value:(id)v2 withUserdefaultMD5Vlaue:(id)v3 { return YES; }
- (id)kn_createBlackFilterWithSerialize:(id)data { return nil; }
- (void)kn_doAddFilterValueForBlackFilter:(id)value {}
- (id)kn_doProcessSerializeForBlackFilter:(id)data { return nil; }
- (void)kn_writeFilterListValue:(id)value withFilterType:(NSInteger)type {}
- (void)kn_initFilterConfigAndVerify {}

// 越狱
- (BOOL)kn_isDeviceJailBreak { return NO; }
- (NSString *)kn_getDeviceJailBreakString { return @""; }
- (NSString *)kn_deviceJailBreakString { return @""; }
- (BOOL)kn_stee_jb_stub { return NO; }
- (BOOL)kn_isJailBroken { return NO; }

// 签名
- (void)kn_checkSignAuthIfNeed:(id)a {}
- (void)kn_processSaveAppSignInfo:(id)a {}

// TuringShield
- (void)kn_getFP:(id)handler {
    if (handler) { void(^blk)(id) = handler; blk(nil); }
}
- (NSDictionary *)kn_blockedFPConfig { return @{}; }
- (void)kn_setBlockedFPConfig:(NSDictionary *)c { [self kn_setBlockedFPConfig:@{}]; }

// OpenUDID
+ (NSString *)kn_openUDIDString { return kn_fakeUDID(); }

// WPK
+ (BOOL)kn_isBeingDebugged { return NO; }

@end

#pragma mark - 入口

static void kn_setup(void) {
    @try {
        NSLog(@"[KN] v3.1 setup start");

        // 0. 先清除本地黑名单缓存
        kn_clearUMengFilterCache();

        // 1. 网络拦截
        [NSURLProtocol registerClass:[KNDeviceProtocol class]];

        // 2. 友盟黑名单 filter (核心！)
        Class umFilter = objc_getClass("UMComBlackAndWhiteFilter");
        if (umFilter) {
            kn_swizzle(umFilter, @selector(doIsBlackFilterValue:withFilterType:), @selector(kn_doIsBlackFilterValue:withFilterType:));
            kn_swizzle(umFilter, @selector(isFilterValueForBlackFilter:), @selector(kn_isFilterValueForBlackFilter:));
            kn_swizzle(umFilter, @selector(createBlackFilterWithSerialize:), @selector(kn_createBlackFilterWithSerialize:));
            kn_swizzle(umFilter, @selector(doAddFilterValueForBlackFilter:), @selector(kn_doAddFilterValueForBlackFilter:));
            kn_swizzle(umFilter, @selector(doProcessSerializeForBlackFilter:), @selector(kn_doProcessSerializeForBlackFilter:));
            kn_swizzle(umFilter, @selector(toStringForBlackFilter), @selector(kn_createBlackFilterWithSerialize:));
            NSLog(@"[KN] UMComBlackAndWhiteFilter hooks installed");
        }

        // UMFilterImprint
        Class umImprint = objc_getClass("UMFilterImprint");
        if (umImprint) {
            kn_swizzle(umImprint, @selector(verifyFilterValue:withImprintMD5Value:withUserdefaultMD5Vlaue:),
                        @selector(kn_verifyFilterValue:withImprintMD5Value:withUserdefaultMD5Vlaue:));
            kn_swizzle(umImprint, @selector(writeFilterListValue:withFilterType:),
                        @selector(kn_writeFilterListValue:withFilterType:));
            kn_swizzle(umImprint, @selector(initFilterConfigAndVerify),
                        @selector(kn_initFilterConfigAndVerify));
            NSLog(@"[KN] UMFilterImprint hooks installed");
        }

        // isBlackDomainUrl: — 可能在多个类上
        NSArray *domainClasses = @[@"MAGNetworkManager", @"MAGAppDelegate", @"MAGHttpClient"];
        for (NSString *name in domainClasses) {
            Class cls = objc_getClass(name.UTF8String);
            if (cls && class_getInstanceMethod(cls, @selector(isBlackDomainUrl:))) {
                kn_swizzle(cls, @selector(isBlackDomainUrl:), @selector(kn_isBlackDomainUrl:));
            }
        }

        // 3. isBlack 模型
        NSArray *modelClasses = @[@"MAGUserModel", @"MAGDeviceModel", @"MAGConfigModel",
                                   @"UserModel", @"DeviceModel", @"ConfigModel",
                                   @"MAGBlackListRecord"];
        for (NSString *name in modelClasses) {
            Class cls = objc_getClass(name.UTF8String);
            if (!cls) continue;
            if (class_getInstanceMethod(cls, @selector(isBlack)))
                kn_swizzle(cls, @selector(isBlack), @selector(kn_isBlack));
            if (class_getInstanceMethod(cls, @selector(setIsBlack:)))
                kn_swizzle(cls, @selector(setIsBlack:), @selector(kn_setIsBlack:));
        }

        // 4. TuringShield
        Class turingCls = objc_getClass("TuringShieldUNBC");
        if (turingCls) {
            kn_swizzle(turingCls, @selector(getFingerprintOnlineWithCompletionHandler:), @selector(kn_getFP:));
        }
        Class gdt = objc_getClass("GDTExpRule");
        if (gdt) {
            kn_swizzle(gdt, @selector(blockedFingerprintConfig), @selector(kn_blockedFPConfig));
            kn_swizzle(gdt, @selector(setBlockedFingerprintConfig:), @selector(kn_setBlockedFPConfig:));
        }

        // 5. OpenUDID
        Class umUtils = objc_getClass("UMUtils");
        if (umUtils) kn_swizzleClass(umUtils, @selector(openUDIDString), @selector(kn_openUDIDString));
        Class openUDIDCls = objc_getClass("OpenUDID");
        if (openUDIDCls) kn_swizzleClass(openUDIDCls, @selector(value), @selector(kn_openUDIDString));
        Class iflyUDID = objc_getClass("IFlyOpenUDID");
        if (iflyUDID) kn_swizzleClass(iflyUDID, @selector(openUDIDString), @selector(kn_openUDIDString));

        // 6. 越狱检测
        NSArray *jbClasses = @[@"MAGAppDelegate", @"MAGNetworkManager", @"MAGUserManager"];
        for (NSString *name in jbClasses) {
            Class cls = objc_getClass(name.UTF8String);
            if (!cls) continue;
            if (class_getInstanceMethod(cls, @selector(isDeviceJailBreak)))
                kn_swizzle(cls, @selector(isDeviceJailBreak), @selector(kn_isDeviceJailBreak));
            if (class_getInstanceMethod(cls, @selector(getDeviceJailBreakString)))
                kn_swizzle(cls, @selector(getDeviceJailBreakString), @selector(kn_getDeviceJailBreakString));
            if (class_getInstanceMethod(cls, @selector(deviceJailBreakString)))
                kn_swizzle(cls, @selector(deviceJailBreakString), @selector(kn_deviceJailBreakString));
            for (int j = 1; j <= 7; j++) {
                NSString *selName = [NSString stringWithFormat:@"stee_isJailbreak_%d", j];
                SEL sel = NSSelectorFromString(selName);
                if (class_getInstanceMethod(cls, sel))
                    kn_swizzle(cls, sel, @selector(kn_stee_jb_stub));
            }
        }
        Class gdtDevMgr = objc_getClass("GDTDeviceManager");
        if (gdtDevMgr && class_getInstanceMethod(gdtDevMgr, @selector(isJailBroken)))
            kn_swizzle(gdtDevMgr, @selector(isJailBroken), @selector(kn_isJailBroken));

        // 7. WPK
        Class wpk = objc_getClass("WPKOOMDetector");
        if (wpk) kn_swizzleClass(wpk, @selector(isBeingDebugged), @selector(kn_isBeingDebugged));

        // 8. 签名
        NSArray *signClasses = @[@"MAGAppDelegate", @"MAGNetworkManager"];
        for (NSString *name in signClasses) {
            Class cls = objc_getClass(name.UTF8String);
            if (!cls) continue;
            if (class_getInstanceMethod(cls, @selector(checkSignAuthIfNeed:)))
                kn_swizzle(cls, @selector(checkSignAuthIfNeed:), @selector(kn_checkSignAuthIfNeed:));
            if (class_getInstanceMethod(cls, @selector(processSaveAppSignInfo:)))
                kn_swizzle(cls, @selector(processSaveAppSignInfo:), @selector(kn_processSaveAppSignInfo:));
        }

        NSLog(@"[KN] v3.1 all hooks installed OK");

    } @catch (NSException *e) {
        NSLog(@"[KN] exception: %@", e);
    }
}

__attribute__((constructor))
static void kn_init(void) {
    // 立即清除缓存（不等延迟）
    @try { kn_clearUMengFilterCache(); } @catch(NSException *e) {}

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        kn_setup();
    });
}
