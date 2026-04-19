// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (v5.0)
// 基于 IDA 逆向分析，精确替换 DeviceUtil udid
// 设备标识来源: Keychain service="udidService" key="udid" (IDFV)
// UA 格式: MAGAPPX|版本|系统|appId|udid|md5_1|md5_2|token

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - Keychain 工具

static void kn_keychainDelete(NSString *service, NSString *key) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: key,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

static NSString *kn_keychainRead(NSString *service, NSString *key) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result) {
        NSString *str = [[NSString alloc] initWithData:(__bridge NSData *)result encoding:NSUTF8StringEncoding];
        CFRelease(result);
        return str;
    }
    return nil;
}

static void kn_keychainWrite(NSString *service, NSString *key, NSString *value) {
    kn_keychainDelete(service, key);
    NSDictionary *attrs = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
    };
    SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
}

// 删除指定 service 下所有条目
static void kn_keychainDeleteService(NSString *service) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

#pragma mark - 假设备 ID

static NSString *kn_fakeUDID(void) {
    static NSString *cached = nil;
    if (cached) return cached;

    // 用我们自己的 key 存储假 ID
    NSString *key = @"kn_bypass_v5";
    cached = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (!cached || cached.length == 0) {
        cached = [[[NSUUID UUID] UUIDString] uppercaseString];
        [[NSUserDefaults standardUserDefaults] setObject:cached forKey:key];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    return cached;
}

#pragma mark - 核心：替换 Keychain 中的 udidService/udid

static void kn_replaceDeviceUDID(void) {
    NSString *fakeID = kn_fakeUDID();

    // 读取当前 Keychain 中的 udid
    NSString *current = kn_keychainRead(@"udidService", @"udid");
    NSLog(@"[KN] Current Keychain udid: %@", current ?: @"(nil)");
    NSLog(@"[KN] Replacing with fake: %@", fakeID);

    // 删除旧的，写入假的
    kn_keychainDeleteService(@"udidService");
    kn_keychainWrite(@"udidService", @"udid", fakeID);

    // 验证
    NSString *verify = kn_keychainRead(@"udidService", @"udid");
    NSLog(@"[KN] Verify Keychain udid: %@", verify ?: @"(nil)");
}

#pragma mark - Hook DeviceUtil udid 返回假 ID

static void kn_hookDeviceUtilUdid(void) {
    Class cls = objc_getClass("DeviceUtil");
    if (!cls) {
        NSLog(@"[KN] DeviceUtil class not found!");
        return;
    }

    SEL sel = NSSelectorFromString(@"udid");
    Method m = class_getClassMethod(cls, sel);
    if (!m) {
        NSLog(@"[KN] DeviceUtil +udid method not found!");
        return;
    }

    NSString *fakeID = kn_fakeUDID();
    IMP newIMP = imp_implementationWithBlock(^NSString *(id self) {
        return fakeID;
    });
    method_setImplementation(m, newIMP);
    NSLog(@"[KN] DeviceUtil +udid hooked -> %@", fakeID);
}

#pragma mark - 清除友盟本地黑名单

static void kn_clearFilterCaches(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [ud dictionaryRepresentation];
    for (NSString *key in all) {
        NSString *lower = [key lowercaseString];
        if ([lower hasPrefix:@"kn_bypass"]) continue;
        if ([lower containsString:@"umeng"] || [lower containsString:@"umfilter"] ||
            [lower containsString:@"umimprint"] || [lower containsString:@"blackfilter"] ||
            [lower containsString:@"filterconfig"] || [lower containsString:@"turing"]) {
            [ud removeObjectForKey:key];
        }
    }
    [ud synchronize];

    NSString *home = NSHomeDirectory();
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *dirs = @[@"Library/Caches", @"Library/Preferences", @"Library", @"Documents"];
    for (NSString *sub in dirs) {
        NSString *dir = [home stringByAppendingPathComponent:sub];
        NSArray *files = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *file in files) {
            NSString *lower = [file lowercaseString];
            if ([lower containsString:@"umeng"] || [lower containsString:@"umfilter"] ||
                [lower containsString:@"umimprint"] || [lower containsString:@"blackfilter"] ||
                [lower containsString:@"filterconfig"] || [lower containsString:@"turing"]) {
                [fm removeItemAtPath:[dir stringByAppendingPathComponent:file] error:nil];
            }
        }
    }
}

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

#pragma mark - 友盟黑名单 Hook

@interface NSObject (KNBypass)
- (BOOL)kn_doIsBlackFilterValue:(id)value withFilterType:(NSInteger)type;
- (BOOL)kn_isFilterValueForBlackFilter:(id)value;
- (id)kn_createBlackFilterWithSerialize:(id)data;
- (void)kn_doAddFilterValueForBlackFilter:(id)value;
- (id)kn_doProcessSerializeForBlackFilter:(id)data;
- (void)kn_writeFilterListValue:(id)value withFilterType:(NSInteger)type;
- (void)kn_initFilterConfigAndVerify;
- (BOOL)kn_isBlackDomainUrl:(id)url;
@end

@implementation NSObject (KNBypass)
- (BOOL)kn_doIsBlackFilterValue:(id)value withFilterType:(NSInteger)type { return NO; }
- (BOOL)kn_isFilterValueForBlackFilter:(id)value { return NO; }
- (id)kn_createBlackFilterWithSerialize:(id)data { return nil; }
- (void)kn_doAddFilterValueForBlackFilter:(id)value {}
- (id)kn_doProcessSerializeForBlackFilter:(id)data { return nil; }
- (void)kn_writeFilterListValue:(id)value withFilterType:(NSInteger)type {}
- (void)kn_initFilterConfigAndVerify {}
- (BOOL)kn_isBlackDomainUrl:(id)url { return NO; }
@end

#pragma mark - 安装辅助 Hook

static void kn_installFilterHooks(void) {
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
        kn_swizzle(umImprint, @selector(writeFilterListValue:withFilterType:), @selector(kn_writeFilterListValue:withFilterType:));
        kn_swizzle(umImprint, @selector(initFilterConfigAndVerify), @selector(kn_initFilterConfigAndVerify));
    }

    // TuringShield
    Class turingCls = objc_getClass("TuringShieldUNBC");
    if (turingCls) {
        Method m = class_getInstanceMethod(turingCls, NSSelectorFromString(@"getFingerprintOnlineWithCompletionHandler:"));
        if (m) {
            method_setImplementation(m, imp_implementationWithBlock(^(id self, void(^h)(id)) { if (h) h(nil); }));
        }
    }

    // GDT blockedFingerprintConfig
    Class gdt = objc_getClass("GDTExpRule");
    if (gdt) {
        Method m1 = class_getInstanceMethod(gdt, NSSelectorFromString(@"blockedFingerprintConfig"));
        if (m1) method_setImplementation(m1, imp_implementationWithBlock(^NSDictionary *(id s) { return @{}; }));
        Method m2 = class_getInstanceMethod(gdt, NSSelectorFromString(@"setBlockedFingerprintConfig:"));
        if (m2) method_setImplementation(m2, imp_implementationWithBlock(^(id s, id c) {}));
    }

    // 网络拦截
    [NSURLProtocol registerClass:[KNDeviceProtocol class]];
}

#pragma mark - 入口

__attribute__((constructor))
static void kn_init(void) {
    @try {
        NSLog(@"[KN] ===== v5.0 init =====");

        // 1. 清除友盟本地黑名单缓存
        kn_clearFilterCaches();

        // 2. 核心：替换 Keychain 中 udidService/udid
        kn_replaceDeviceUDID();

        NSLog(@"[KN] Keychain replaced, waiting for classes to load...");
    } @catch (NSException *e) {
        NSLog(@"[KN] init exception: %@", e);
    }

    // 3. Hook 部分短延迟等类加载
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            // 核心 hook: DeviceUtil +udid
            kn_hookDeviceUtilUdid();

            // 辅助 hook: 友盟 filter + TuringShield + 网络拦截
            kn_installFilterHooks();

            NSLog(@"[KN] ===== v5.0 all hooks installed =====");
        } @catch (NSException *e) {
            NSLog(@"[KN] hook exception: %@", e);
        }
    });
}
