// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (v4.0)
// 兼容: iOS 14+ / 巨魔注入 / 轻松签注入
// 策略: constructor 同步执行，不延迟。先清+写 Keychain，再 hook 所有读取方法

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
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

static void kn_replaceIMP(const char *clsName, SEL sel, id block, BOOL isClassMethod) {
    Class cls = objc_getClass(clsName);
    if (!cls) return;
    Method m = isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
    if (!m) return;
    method_setImplementation(m, imp_implementationWithBlock(block));
}

#pragma mark - Keychain 工具

static void kn_keychainDelete(NSString *service) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

static void kn_keychainWrite(NSString *service, NSString *value) {
    kn_keychainDelete(service);
    NSDictionary *attrs = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
    };
    SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
}

#pragma mark - 假设备 ID

// 用 Keychain 自身存储假 ID，确保跨 APP 生命周期一致
// 但每次注入新 dylib 时会重新生成（通过版本标记）
static NSString *kn_fakeUDID(void) {
    static NSString *cached = nil;
    if (cached) return cached;

    // 检查是否已有我们自己写入的假 ID
    NSString *key = @"kn_bypass_fake_udid_v4";
    NSString *stored = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (stored.length > 0) {
        cached = stored;
        return cached;
    }

    // 生成新的假 UUID
    cached = [[NSUUID UUID] UUIDString];
    [[NSUserDefaults standardUserDefaults] setObject:cached forKey:key];
    [[NSUserDefaults standardUserDefaults] synchronize];
    return cached;
}

#pragma mark - 清除并替换 Keychain 中所有设备 ID

static void kn_replaceKeychainIDs(void) {
    NSString *fakeID = kn_fakeUDID();

    // OpenUDID slots
    for (int i = 0; i < 20; i++) {
        NSString *svc = [NSString stringWithFormat:@"org.OpenUDID.slot.%d", i];
        kn_keychainDelete(svc);
    }
    kn_keychainDelete(@"kOpenUDIDKC");
    kn_keychainWrite(@"kOpenUDIDKC", fakeID);

    // 微博 SDK
    kn_keychainDelete(@"kWBSDKKeyChainUDID");
    kn_keychainDelete(@"kWBSDKKeyChainNEWUDID");
    kn_keychainWrite(@"kWBSDKKeyChainUDID", fakeID);
    kn_keychainWrite(@"kWBSDKKeyChainNEWUDID", fakeID);

    // 百度地图
    kn_keychainDelete(@"BMKBaseUDID");
    kn_keychainDelete(@"BMKLocSDKUDID");
    kn_keychainWrite(@"BMKBaseUDID", fakeID);
    kn_keychainWrite(@"BMKLocSDKUDID", fakeID);

    // WPK
    NSString *home = NSHomeDirectory();
    NSString *wpkDir = [home stringByAppendingPathComponent:@"Documents/wpkdata"];
    [[NSFileManager defaultManager] createDirectoryAtPath:wpkDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *wpkPath = [wpkDir stringByAppendingPathComponent:@"myudid"];
    [fakeID writeToFile:wpkPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

#pragma mark - 清除 NSUserDefaults 中旧的设备标识

static void kn_clearUserDefaults(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [ud dictionaryRepresentation];
    for (NSString *key in all) {
        NSString *lower = [key lowercaseString];
        // 不删除我们自己的 key
        if ([lower hasPrefix:@"kn_bypass"]) continue;
        if ([lower containsString:@"openudid"] ||
            [lower containsString:@"umeng"] ||
            [lower containsString:@"umfilter"] ||
            [lower containsString:@"umimprint"] ||
            [lower containsString:@"turing"] ||
            [lower containsString:@"deviceid"] ||
            [lower containsString:@"device_id"] ||
            [lower containsString:@"udid"] ||
            [lower containsString:@"bmkloc"] ||
            [lower containsString:@"bmkbase"] ||
            [lower containsString:@"ifly"] ||
            [lower containsString:@"eaccount"] ||
            [lower containsString:@"stee_"] ||
            [lower containsString:@"blackfilter"] ||
            [lower containsString:@"filterconfig"] ||
            [lower containsString:@"wpk"] ||
            [lower containsString:@"wbsdk"]) {
            [ud removeObjectForKey:key];
        }
    }
    [ud synchronize];

    // 清除友盟 filter 文件
    NSString *home = NSHomeDirectory();
    NSArray *searchDirs = @[@"Library/Caches", @"Library/Preferences", @"Library", @"Documents"];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *sub in searchDirs) {
        NSString *dir = [home stringByAppendingPathComponent:sub];
        NSArray *files = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *file in files) {
            NSString *lower = [file lowercaseString];
            if ([lower containsString:@"umeng"] || [lower containsString:@"umfilter"] ||
                [lower containsString:@"umimprint"] || [lower containsString:@"blackfilter"] ||
                [lower containsString:@"filterconfig"] || [lower containsString:@"filterlist"] ||
                [lower containsString:@"turing"] || [lower containsString:@"openudid"]) {
                [fm removeItemAtPath:[dir stringByAppendingPathComponent:file] error:nil];
            }
        }
    }
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
- (void)kn_setIsBlack:(BOOL)v;
- (BOOL)kn_isBlack;
- (BOOL)kn_doIsBlackFilterValue:(id)value withFilterType:(NSInteger)type;
- (BOOL)kn_isBlackDomainUrl:(id)url;
- (BOOL)kn_isFilterValueForBlackFilter:(id)value;
- (BOOL)kn_verifyFilterValue:(id)v1 withImprintMD5Value:(id)v2 withUserdefaultMD5Vlaue:(id)v3;
- (id)kn_createBlackFilterWithSerialize:(id)data;
- (void)kn_doAddFilterValueForBlackFilter:(id)value;
- (id)kn_doProcessSerializeForBlackFilter:(id)data;
- (void)kn_writeFilterListValue:(id)value withFilterType:(NSInteger)type;
- (void)kn_initFilterConfigAndVerify;
- (BOOL)kn_isDeviceJailBreak;
- (NSString *)kn_getDeviceJailBreakString;
- (NSString *)kn_deviceJailBreakString;
- (BOOL)kn_stee_jb_stub;
- (void)kn_checkSignAuthIfNeed:(id)a;
- (void)kn_processSaveAppSignInfo:(id)a;
+ (NSString *)kn_openUDIDString;
+ (BOOL)kn_isBeingDebugged;
@end

@implementation NSObject (KNBypass)
- (void)kn_setIsBlack:(BOOL)v { [self kn_setIsBlack:NO]; }
- (BOOL)kn_isBlack { return NO; }
- (BOOL)kn_doIsBlackFilterValue:(id)value withFilterType:(NSInteger)type { return NO; }
- (BOOL)kn_isBlackDomainUrl:(id)url { return NO; }
- (BOOL)kn_isFilterValueForBlackFilter:(id)value { return NO; }
- (BOOL)kn_verifyFilterValue:(id)v1 withImprintMD5Value:(id)v2 withUserdefaultMD5Vlaue:(id)v3 { return YES; }
- (id)kn_createBlackFilterWithSerialize:(id)data { return nil; }
- (void)kn_doAddFilterValueForBlackFilter:(id)value {}
- (id)kn_doProcessSerializeForBlackFilter:(id)data { return nil; }
- (void)kn_writeFilterListValue:(id)value withFilterType:(NSInteger)type {}
- (void)kn_initFilterConfigAndVerify {}
- (BOOL)kn_isDeviceJailBreak { return NO; }
- (NSString *)kn_getDeviceJailBreakString { return @""; }
- (NSString *)kn_deviceJailBreakString { return @""; }
- (BOOL)kn_stee_jb_stub { return NO; }
- (void)kn_checkSignAuthIfNeed:(id)a {}
- (void)kn_processSaveAppSignInfo:(id)a {}
+ (NSString *)kn_openUDIDString { return kn_fakeUDID(); }
+ (BOOL)kn_isBeingDebugged { return NO; }
@end

#pragma mark - 安装所有 hook（同步执行）

static void kn_installHooks(void) {
    NSString *fakeID = kn_fakeUDID();
    NSString *fakeMD5 = [[fakeID stringByReplacingOccurrencesOfString:@"-" withString:@""] substringToIndex:32];

    // ===== 设备 ID 替换 =====
    kn_replaceIMP("UMUtils", @selector(openUDIDString), ^NSString *(id s) { return fakeID; }, YES);
    kn_replaceIMP("OpenUDID", @selector(value), ^NSString *(id s) { return fakeID; }, YES);
    kn_replaceIMP("IFlyOpenUDID", @selector(openUDIDString), ^NSString *(id s) { return fakeID; }, YES);
    kn_replaceIMP("BMKBaseUDID", @selector(getUDID), ^NSString *(id s) { return fakeID; }, YES);
    kn_replaceIMP("BMKLocSDKUDID", @selector(getUDID), ^NSString *(id s) { return fakeID; }, YES);
    kn_replaceIMP("BMKBaseDeviceIdentifierFetcher", @selector(getDeviceId), ^NSString *(id s) { return fakeID; }, NO);
    kn_replaceIMP("BMKLocationDeviceIdentifierFetcher", @selector(getDeviceId), ^NSString *(id s) { return fakeID; }, NO);
    kn_replaceIMP("IFlyDeviceIdentifier", @selector(getDeviceId), ^NSString *(id s) { return fakeID; }, YES);
    kn_replaceIMP("EAccountLibLogDeviceId", @selector(getLibLogDeviceId), ^NSString *(id s) { return fakeID; }, YES);
    kn_replaceIMP("EAccountLibLogDeviceId", @selector(loadLibLogDeviceId), ^NSString *(id s) { return fakeID; }, YES);

    // internalGetDeviceUDID / deviceUDID / udid / externalUdid / wbsdk_plainDeviceID
    // 这些可能在多个类上，用 NSObject 兜底
    kn_replaceIMP("NSObject", NSSelectorFromString(@"internalGetDeviceUDID"), ^NSString *(id s) { return fakeID; }, NO);
    kn_replaceIMP("NSObject", NSSelectorFromString(@"uniqueGlobalDeviceIdentifier"), ^NSString *(id s) { return fakeID; }, NO);
    kn_replaceIMP("NSObject", NSSelectorFromString(@"wbsdk_plainDeviceID"), ^NSString *(id s) { return fakeID; }, NO);
    kn_replaceIMP("NSObject", NSSelectorFromString(@"stee_deviceIDs"), ^NSString *(id s) { return fakeID; }, NO);
    kn_replaceIMP("NSObject", NSSelectorFromString(@"deviceUUID"), ^NSString *(id s) { return fakeID; }, NO);
    kn_replaceIMP("NSObject", NSSelectorFromString(@"getUUID"), ^NSString *(id s) { return fakeID; }, NO);

    // TuringShield
    kn_replaceIMP("TuringShieldUNBC", @selector(getFingerprintOnlineWithCompletionHandler:),
        ^(id s, void(^h)(id)) { if (h) h(nil); }, NO);

    // GDT
    kn_replaceIMP("GDTExpRule", NSSelectorFromString(@"blockedFingerprintConfig"), ^NSDictionary *(id s) { return @{}; }, NO);
    kn_replaceIMP("GDTExpRule", NSSelectorFromString(@"setBlockedFingerprintConfig:"), ^(id s, id c) {}, NO);
    kn_replaceIMP("GDTDeviceManager", NSSelectorFromString(@"isJailBroken"), ^BOOL(id s) { return NO; }, NO);

    // ===== 友盟黑名单 =====
    Class umFilter = objc_getClass("UMComBlackAndWhiteFilter");
    if (umFilter) {
        kn_swizzle(umFilter, @selector(doIsBlackFilterValue:withFilterType:), @selector(kn_doIsBlackFilterValue:withFilterType:));
        kn_swizzle(umFilter, @selector(isFilterValueForBlackFilter:), @selector(kn_isFilterValueForBlackFilter:));
        kn_swizzle(umFilter, @selector(createBlackFilterWithSerialize:), @selector(kn_createBlackFilterWithSerialize:));
        kn_swizzle(umFilter, @selector(doAddFilterValueForBlackFilter:), @selector(kn_doAddFilterValueForBlackFilter:));
        kn_swizzle(umFilter, @selector(doProcessSerializeForBlackFilter:), @selector(kn_doProcessSerializeForBlackFilter:));
    }
    Class umImprint = objc_getClass("UMFilterImprint");
    if (umImprint) {
        kn_swizzle(umImprint, @selector(verifyFilterValue:withImprintMD5Value:withUserdefaultMD5Vlaue:),
                    @selector(kn_verifyFilterValue:withImprintMD5Value:withUserdefaultMD5Vlaue:));
        kn_swizzle(umImprint, @selector(writeFilterListValue:withFilterType:),
                    @selector(kn_writeFilterListValue:withFilterType:));
        kn_swizzle(umImprint, @selector(initFilterConfigAndVerify), @selector(kn_initFilterConfigAndVerify));
    }
    NSArray *domainClasses = @[@"MAGNetworkManager", @"MAGAppDelegate", @"MAGHttpClient"];
    for (NSString *name in domainClasses) {
        Class cls = objc_getClass(name.UTF8String);
        if (cls && class_getInstanceMethod(cls, @selector(isBlackDomainUrl:)))
            kn_swizzle(cls, @selector(isBlackDomainUrl:), @selector(kn_isBlackDomainUrl:));
    }

    // ===== isBlack =====
    NSArray *modelClasses = @[@"MAGUserModel", @"MAGDeviceModel", @"MAGConfigModel",
                               @"UserModel", @"DeviceModel", @"ConfigModel", @"MAGBlackListRecord"];
    for (NSString *name in modelClasses) {
        Class cls = objc_getClass(name.UTF8String);
        if (!cls) continue;
        if (class_getInstanceMethod(cls, @selector(isBlack)))
            kn_swizzle(cls, @selector(isBlack), @selector(kn_isBlack));
        if (class_getInstanceMethod(cls, @selector(setIsBlack:)))
            kn_swizzle(cls, @selector(setIsBlack:), @selector(kn_setIsBlack:));
    }

    // ===== 越狱检测 =====
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
            SEL sel = NSSelectorFromString([NSString stringWithFormat:@"stee_isJailbreak_%d", j]);
            if (class_getInstanceMethod(cls, sel))
                kn_swizzle(cls, sel, @selector(kn_stee_jb_stub));
        }
    }

    // ===== WPK =====
    Class wpk = objc_getClass("WPKOOMDetector");
    if (wpk) kn_swizzleClass(wpk, @selector(isBeingDebugged), @selector(kn_isBeingDebugged));

    // ===== 签名 =====
    NSArray *signClasses = @[@"MAGAppDelegate", @"MAGNetworkManager"];
    for (NSString *name in signClasses) {
        Class cls = objc_getClass(name.UTF8String);
        if (!cls) continue;
        if (class_getInstanceMethod(cls, @selector(checkSignAuthIfNeed:)))
            kn_swizzle(cls, @selector(checkSignAuthIfNeed:), @selector(kn_checkSignAuthIfNeed:));
        if (class_getInstanceMethod(cls, @selector(processSaveAppSignInfo:)))
            kn_swizzle(cls, @selector(processSaveAppSignInfo:), @selector(kn_processSaveAppSignInfo:));
    }

    // ===== 网络拦截 =====
    [NSURLProtocol registerClass:[KNDeviceProtocol class]];
}

#pragma mark - 入口（同步执行，不延迟！）

__attribute__((constructor))
static void kn_init(void) {
    @try {
        // 1. 先清除旧的设备标识
        kn_clearUserDefaults();

        // 2. 替换 Keychain 中的设备 ID 为假 ID
        kn_replaceKeychainIDs();

        // 3. 立即安装所有 hook（不延迟！）
        kn_installHooks();

        NSLog(@"[KN] v4.0 installed, fakeID=%@", kn_fakeUDID());
    } @catch (NSException *e) {
        NSLog(@"[KN] init exception: %@", e);
    }
}
