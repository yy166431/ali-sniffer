// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (v3.2)
// 兼容: iOS 14+ / 巨魔注入 / 轻松签注入
// 核心: 全面替换设备标识 + 清除本地缓存 + 拦截网络请求

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

// 用 IMP 替换指定类的实例方法（不需要 swizzle 对）
static void kn_replaceInstance(const char *clsName, SEL sel, id block) {
    Class cls = objc_getClass(clsName);
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    method_setImplementation(m, imp_implementationWithBlock(block));
}

// 用 IMP 替换指定类的类方法
static void kn_replaceClass(const char *clsName, SEL sel, id block) {
    Class cls = objc_getClass(clsName);
    if (!cls) return;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return;
    method_setImplementation(m, imp_implementationWithBlock(block));
}

#pragma mark - 持久化假设备 ID（删 APP 重装就换新）

static NSString *kn_fakeUDID(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    NSString *key = @"kn_fake_udid_v3";
    cached = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (!cached || cached.length == 0) {
        cached = [[NSUUID UUID] UUIDString];
        [[NSUserDefaults standardUserDefaults] setObject:cached forKey:key];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    return cached;
}

// 假设备名 MD5（固定，看起来像真的）
static NSString *kn_fakeDeviceNameMD5(void) {
    // 用 fakeUDID 的前32位当 MD5
    NSString *udid = kn_fakeUDID();
    return [[udid stringByReplacingOccurrencesOfString:@"-" withString:@""] substringToIndex:32];
}

#pragma mark - 清除所有本地设备标识缓存

static void kn_clearAllDeviceCaches(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *home = NSHomeDirectory();

    // 1. 删除 wpkdata/myudid 文件
    NSString *wpkPath = [home stringByAppendingPathComponent:@"Documents/wpkdata/myudid"];
    [fm removeItemAtPath:wpkPath error:nil];

    // 2. 删除 wpkdata 目录
    NSString *wpkDir = [home stringByAppendingPathComponent:@"Documents/wpkdata"];
    [fm removeItemAtPath:wpkDir error:nil];

    // 3. 清除 NSUserDefaults 中所有设备标识相关 key
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [ud dictionaryRepresentation];
    for (NSString *key in all) {
        NSString *lower = [key lowercaseString];
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
            [lower containsString:@"wpk"]) {
            [ud removeObjectForKey:key];
        }
    }
    [ud synchronize];

    // 4. 清除友盟 filter 文件
    NSArray *searchDirs = @[@"Library/Caches", @"Library/Preferences", @"Library", @"Documents"];
    for (NSString *sub in searchDirs) {
        NSString *dir = [home stringByAppendingPathComponent:sub];
        NSArray *files = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *file in files) {
            NSString *lower = [file lowercaseString];
            if ([lower containsString:@"umeng"] ||
                [lower containsString:@"umfilter"] ||
                [lower containsString:@"umimprint"] ||
                [lower containsString:@"blackfilter"] ||
                [lower containsString:@"filterconfig"] ||
                [lower containsString:@"filterlist"] ||
                [lower containsString:@"turing"] ||
                [lower containsString:@"openudid"]) {
                [fm removeItemAtPath:[dir stringByAppendingPathComponent:file] error:nil];
            }
        }
    }

    // 5. 清除 Keychain 中 OpenUDID 相关条目
    @try {
        NSMutableDictionary *query = [NSMutableDictionary dictionary];
        query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
        // OpenUDID 用 "org.OpenUDID.slot.X" 作为 service
        for (int i = 0; i < 20; i++) {
            query[(__bridge id)kSecAttrService] = [NSString stringWithFormat:@"org.OpenUDID.slot.%d", i];
            SecItemDelete((__bridge CFDictionaryRef)query);
        }
        // 也清除 kOpenUDIDKC
        query[(__bridge id)kSecAttrService] = @"kOpenUDIDKC";
        SecItemDelete((__bridge CFDictionaryRef)query);
        // BMK UDID
        query[(__bridge id)kSecAttrService] = @"BMKBaseUDID";
        SecItemDelete((__bridge CFDictionaryRef)query);
        query[(__bridge id)kSecAttrService] = @"BMKLocSDKUDID";
        SecItemDelete((__bridge CFDictionaryRef)query);
    } @catch (NSException *e) {}
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

#pragma mark - Hook 实现（NSObject category）

@interface NSObject (KNBypass)
// isBlack
- (void)kn_setIsBlack:(BOOL)v;
- (BOOL)kn_isBlack;
// 友盟黑名单
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
// 签名
- (void)kn_checkSignAuthIfNeed:(id)a;
- (void)kn_processSaveAppSignInfo:(id)a;
// OpenUDID
+ (NSString *)kn_openUDIDString;
// WPK
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

#pragma mark - 入口

static void kn_setup(void) {
    @try {
        NSLog(@"[KN] v3.2 setup start, fakeUDID=%@", kn_fakeUDID());

        // 1. 网络拦截
        [NSURLProtocol registerClass:[KNDeviceProtocol class]];

        // ========== 2. 全面替换设备标识 ==========

        NSString *fakeUDID = kn_fakeUDID();
        NSString *fakeMD5 = kn_fakeDeviceNameMD5();

        // 2a. OpenUDID (多个 SDK 都用)
        kn_replaceClass("UMUtils", @selector(openUDIDString), ^NSString *(id self) { return fakeUDID; });
        kn_replaceClass("OpenUDID", @selector(value), ^NSString *(id self) { return fakeUDID; });
        kn_replaceClass("IFlyOpenUDID", @selector(openUDIDString), ^NSString *(id self) { return fakeUDID; });

        // 2b. uniqueGlobalDeviceIdentifier (全局设备标识)
        kn_replaceInstance("UIDevice", @selector(uniqueGlobalDeviceIdentifier), ^NSString *(id self) { return fakeUDID; });

        // 2c. BMK 百度地图 UDID
        kn_replaceClass("BMKBaseUDID", @selector(getUDID), ^NSString *(id self) { return fakeUDID; });
        kn_replaceClass("BMKLocSDKUDID", @selector(getUDID), ^NSString *(id self) { return fakeUDID; });
        // BMKBaseDeviceIdentifierFetcher
        kn_replaceInstance("BMKBaseDeviceIdentifierFetcher", @selector(getDeviceId), ^NSString *(id self) { return fakeUDID; });
        kn_replaceInstance("BMKLocationDeviceIdentifierFetcher", @selector(getDeviceId), ^NSString *(id self) { return fakeUDID; });

        // 2d. 讯飞 IFlyDeviceIdentifier
        kn_replaceClass("IFlyDeviceIdentifier", @selector(getDeviceId), ^NSString *(id self) { return fakeUDID; });

        // 2e. 阿里安全 stee_deviceIDs
        kn_replaceInstance("NSObject", @selector(stee_deviceIDs), ^NSString *(id self) { return fakeUDID; });

        // 2f. EAccountLib 设备 ID
        kn_replaceClass("EAccountLibLogDeviceId", @selector(getLibLogDeviceId), ^NSString *(id self) { return fakeUDID; });
        kn_replaceClass("EAccountLibLogDeviceId", @selector(loadLibLogDeviceId), ^NSString *(id self) { return fakeUDID; });

        // 2g. DeviceNameMD5
        kn_replaceInstance("NSObject", @selector(getDeviceNameMD5WithError:), ^NSString *(id self, id err) { return fakeMD5; });

        // 2h. WPK myudid
        kn_replaceInstance("NSObject", @selector(deviceUUID), ^NSString *(id self) { return fakeUDID; });
        kn_replaceInstance("NSObject", @selector(getUUID), ^NSString *(id self) { return fakeUDID; });

        // 2i. TuringShield 指纹
        kn_replaceInstance("TuringShieldUNBC", @selector(getFingerprintOnlineWithCompletionHandler:),
            ^(id self, void(^handler)(id)) { if (handler) handler(nil); });

        // 2j. GDTExpRule blockedFingerprintConfig
        kn_replaceInstance("GDTExpRule", @selector(blockedFingerprintConfig), ^NSDictionary *(id self) { return @{}; });
        kn_replaceInstance("GDTExpRule", @selector(setBlockedFingerprintConfig:), ^(id self, id cfg) {});

        // 2k. GDTDeviceManager isJailBroken
        kn_replaceInstance("GDTDeviceManager", @selector(isJailBroken), ^BOOL(id self) { return NO; });

        NSLog(@"[KN] Device ID hooks installed");

        // ========== 3. 友盟黑名单 filter ==========

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
            kn_swizzle(umImprint, @selector(initFilterConfigAndVerify),
                        @selector(kn_initFilterConfigAndVerify));
        }

        // isBlackDomainUrl:
        NSArray *domainClasses = @[@"MAGNetworkManager", @"MAGAppDelegate", @"MAGHttpClient"];
        for (NSString *name in domainClasses) {
            Class cls = objc_getClass(name.UTF8String);
            if (cls && class_getInstanceMethod(cls, @selector(isBlackDomainUrl:)))
                kn_swizzle(cls, @selector(isBlackDomainUrl:), @selector(kn_isBlackDomainUrl:));
        }

        NSLog(@"[KN] UMeng filter hooks installed");

        // ========== 4. isBlack 模型 ==========

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

        // ========== 5. 越狱检测 ==========

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

        // ========== 6. WPK 调试检测 ==========

        Class wpk = objc_getClass("WPKOOMDetector");
        if (wpk) kn_swizzleClass(wpk, @selector(isBeingDebugged), @selector(kn_isBeingDebugged));

        // ========== 7. 签名检测 ==========

        NSArray *signClasses = @[@"MAGAppDelegate", @"MAGNetworkManager"];
        for (NSString *name in signClasses) {
            Class cls = objc_getClass(name.UTF8String);
            if (!cls) continue;
            if (class_getInstanceMethod(cls, @selector(checkSignAuthIfNeed:)))
                kn_swizzle(cls, @selector(checkSignAuthIfNeed:), @selector(kn_checkSignAuthIfNeed:));
            if (class_getInstanceMethod(cls, @selector(processSaveAppSignInfo:)))
                kn_swizzle(cls, @selector(processSaveAppSignInfo:), @selector(kn_processSaveAppSignInfo:));
        }

        NSLog(@"[KN] v3.2 all hooks installed OK");

    } @catch (NSException *e) {
        NSLog(@"[KN] exception: %@", e);
    }
}

__attribute__((constructor))
static void kn_init(void) {
    // 立即清除所有设备标识缓存
    @try { kn_clearAllDeviceCaches(); } @catch(NSException *e) {}

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        kn_setup();
    });
}
