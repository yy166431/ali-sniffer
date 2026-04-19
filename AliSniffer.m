// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (v6.0)
// 基于 IDA 完整逆向分析
// 策略: 直接 hook UA 构建函数，替换 udid 和重算 MD5

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - MD5 工具

static NSString *kn_md5(NSString *input) {
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), digest);
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    return output;
}

#pragma mark - Keychain 工具

static void kn_keychainDeleteService(NSString *service) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

static void kn_keychainWrite(NSString *service, NSString *key, NSString *value) {
    // 先删
    NSDictionary *delQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: key,
    };
    SecItemDelete((__bridge CFDictionaryRef)delQuery);
    // 再写
    NSDictionary *attrs = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
    };
    SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
}

#pragma mark - 假设备 ID

static NSString *kn_fakeUDID(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    NSString *key = @"kn_bypass_v6";
    cached = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (!cached || cached.length == 0) {
        cached = [[[NSUUID UUID] UUIDString] uppercaseString];
        [[NSUserDefaults standardUserDefaults] setObject:cached forKey:key];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    return cached;
}

#pragma mark - 核心 Hook: userAgentWithoutTokenValues

// 原始方法的 IMP 保存
static id (*orig_userAgentWithoutTokenValues)(id, SEL);

// 替换后的实现：修改返回数组中的 udid 和 MD5
static id kn_userAgentWithoutTokenValues(id self, SEL _cmd) {
    // 调用原始方法获取数组
    id origArray = orig_userAgentWithoutTokenValues(self, _cmd);
    if (!origArray) return origArray;

    NSMutableArray *arr = [origArray mutableCopy];
    if (arr.count < 7) return origArray;

    // arr[0] = "MAGAPPX"
    // arr[1] = 版本号
    // arr[2] = 系统信息
    // arr[3] = magAppId (经过空值检查)
    // arr[4] = DeviceUtil udid (经过空值检查) ← 替换这个
    // arr[5] = MD5(arr[3] + "magapp" + arr[4] + signSecret) ← 重算
    // arr[6] = MD5(MD5("magcloud") + arr[4] + "mag_app_cloud" + arr[3] + MD5("nanjingxinxi")) ← 重算

    NSString *fakeID = kn_fakeUDID();
    NSString *appId = arr[3];

    // 替换 udid
    arr[4] = fakeID;

    // 获取 signSecret
    Class appConfigCls = objc_getClass("AppConfig");
    NSString *signSecret = @"";
    if (appConfigCls) {
        id config = ((id (*)(id, SEL))objc_msgSend)(appConfigCls, NSSelectorFromString(@"config"));
        if (config) {
            signSecret = ((id (*)(id, SEL))objc_msgSend)(config, NSSelectorFromString(@"signSecret"));
            if (!signSecret) signSecret = @"";
        }
    }

    // 重算 md5_1: MD5(appId + "magapp" + udid + signSecret)
    NSString *md5_1_input = [NSString stringWithFormat:@"%@%@%@%@", appId, @"magapp", fakeID, signSecret];
    arr[5] = kn_md5(md5_1_input);

    // 重算 md5_2: MD5(MD5("magcloud") + udid + "mag_app_cloud" + appId + MD5("nanjingxinxi"))
    NSString *md5_2_input = [NSString stringWithFormat:@"%@%@%@%@%@",
        kn_md5(@"magcloud"), fakeID, @"mag_app_cloud", appId, kn_md5(@"nanjingxinxi")];
    arr[6] = kn_md5(md5_2_input);

    NSLog(@"[KN] UA patched: udid=%@, md5_1=%@, md5_2=%@", fakeID, arr[5], arr[6]);

    return [arr copy];
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

#pragma mark - 友盟黑名单 Hook

@interface NSObject (KNBypass)
- (BOOL)kn_doIsBlackFilterValue:(id)value withFilterType:(NSInteger)type;
- (BOOL)kn_isFilterValueForBlackFilter:(id)value;
- (id)kn_createBlackFilterWithSerialize:(id)data;
- (void)kn_doAddFilterValueForBlackFilter:(id)value;
- (void)kn_initFilterConfigAndVerify;
@end

@implementation NSObject (KNBypass)
- (BOOL)kn_doIsBlackFilterValue:(id)value withFilterType:(NSInteger)type { return NO; }
- (BOOL)kn_isFilterValueForBlackFilter:(id)value { return NO; }
- (id)kn_createBlackFilterWithSerialize:(id)data { return nil; }
- (void)kn_doAddFilterValueForBlackFilter:(id)value {}
- (void)kn_initFilterConfigAndVerify {}
@end

#pragma mark - 入口

__attribute__((constructor))
static void kn_init(void) {
    @try {
        NSString *fakeID = kn_fakeUDID();
        NSLog(@"[KN] ===== v6.0 init, fakeUDID=%@ =====", fakeID);

        // 1. 替换 Keychain 中的 udidService/udid（以防万一）
        kn_keychainDeleteService(@"udidService");
        kn_keychainWrite(@"udidService", @"udid", fakeID);

        // 2. 清除友盟缓存
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

        NSLog(@"[KN] Keychain + cache cleared");
    } @catch (NSException *e) {
        NSLog(@"[KN] init exception: %@", e);
    }

    // 3. Hook 部分用短延迟
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            // 核心: hook userAgentWithoutTokenValues（类方法）
            Class headerCls = objc_getClass("MAGApiRequestHeaderProvider");
            if (headerCls) {
                SEL sel = NSSelectorFromString(@"userAgentWithoutTokenValues");
                Method m = class_getClassMethod(headerCls, sel);
                if (m) {
                    orig_userAgentWithoutTokenValues = (id(*)(id, SEL))method_getImplementation(m);
                    method_setImplementation(m, (IMP)kn_userAgentWithoutTokenValues);
                    NSLog(@"[KN] userAgentWithoutTokenValues hooked!");
                }
            }

            // 也 hook DeviceUtil udid（双保险）
            Class deviceCls = objc_getClass("DeviceUtil");
            if (deviceCls) {
                SEL sel = NSSelectorFromString(@"udid");
                Method m = class_getClassMethod(deviceCls, sel);
                if (m) {
                    NSString *fakeID = kn_fakeUDID();
                    method_setImplementation(m, imp_implementationWithBlock(^NSString *(id self) {
                        return fakeID;
                    }));
                    NSLog(@"[KN] DeviceUtil +udid hooked!");
                }
            }

            // 友盟黑名单
            Class umFilter = objc_getClass("UMComBlackAndWhiteFilter");
            if (umFilter) {
                kn_swizzle(umFilter, @selector(doIsBlackFilterValue:withFilterType:), @selector(kn_doIsBlackFilterValue:withFilterType:));
                kn_swizzle(umFilter, @selector(isFilterValueForBlackFilter:), @selector(kn_isFilterValueForBlackFilter:));
                kn_swizzle(umFilter, @selector(createBlackFilterWithSerialize:), @selector(kn_createBlackFilterWithSerialize:));
                kn_swizzle(umFilter, @selector(doAddFilterValueForBlackFilter:), @selector(kn_doAddFilterValueForBlackFilter:));
            }
            Class umImprint = objc_getClass("UMFilterImprint");
            if (umImprint) {
                kn_swizzle(umImprint, @selector(initFilterConfigAndVerify), @selector(kn_initFilterConfigAndVerify));
            }

            // TuringShield
            Class turingCls = objc_getClass("TuringShieldUNBC");
            if (turingCls) {
                Method m = class_getInstanceMethod(turingCls, NSSelectorFromString(@"getFingerprintOnlineWithCompletionHandler:"));
                if (m) method_setImplementation(m, imp_implementationWithBlock(^(id s, void(^h)(id)) { if (h) h(nil); }));
            }

            // 网络拦截
            [NSURLProtocol registerClass:[KNDeviceProtocol class]];

            NSLog(@"[KN] ===== v6.0 all hooks installed =====");
        } @catch (NSException *e) {
            NSLog(@"[KN] hook exception: %@", e);
        }
    });
}
