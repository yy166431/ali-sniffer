// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (v7.0)
// 策略: 拦截所有 HTTP 请求，在发出前替换 User-Agent 中的设备 ID
// 这是最底层的拦截，无论 APP 怎么构建 UA，最终都要经过 NSURLSession

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - MD5

static NSString *kn_md5(NSString *input) {
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), digest);
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    return output;
}

#pragma mark - 假设备 ID

static NSString *kn_fakeUDID(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    NSString *key = @"kn_bypass_v7";
    cached = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (!cached || cached.length == 0) {
        cached = [[[NSUUID UUID] UUIDString] uppercaseString];
        [[NSUserDefaults standardUserDefaults] setObject:cached forKey:key];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    return cached;
}

#pragma mark - UA 替换逻辑

// UA 格式: MAGAPPX|版本|系统|appId|udid|md5_1|md5_2|token
// 用 | 分割，替换 index 4 (udid)，重算 index 5 和 6
static NSString *kn_patchUserAgent(NSString *originalUA) {
    if (!originalUA || originalUA.length == 0) return originalUA;
    if (![originalUA hasPrefix:@"MAGAPPX"]) return originalUA;

    // 可能有 webViewUA 前缀: "webViewUA MAGAPPX|..."
    // 找到 MAGAPPX 的位置
    NSRange magRange = [originalUA rangeOfString:@"MAGAPPX"];
    if (magRange.location == NSNotFound) return originalUA;

    NSString *prefix = @"";
    NSString *magPart = originalUA;
    if (magRange.location > 0) {
        prefix = [originalUA substringToIndex:magRange.location];
        magPart = [originalUA substringFromIndex:magRange.location];
    }

    NSArray *parts = [magPart componentsSeparatedByString:@"|"];
    if (parts.count < 7) return originalUA;

    NSMutableArray *newParts = [parts mutableCopy];
    NSString *fakeID = kn_fakeUDID();
    NSString *appId = newParts[3];

    // 替换 udid
    newParts[4] = fakeID;

    // 重算 md5_1: MD5(appId + "magapp" + udid + signSecret)
    // signSecret 从 AppConfig 获取
    NSString *signSecret = @"";
    Class appConfigCls = objc_getClass("AppConfig");
    if (appConfigCls) {
        @try {
            id config = ((id (*)(id, SEL))objc_msgSend)(appConfigCls, NSSelectorFromString(@"config"));
            if (config) {
                id secret = ((id (*)(id, SEL))objc_msgSend)(config, NSSelectorFromString(@"signSecret"));
                if (secret && [secret isKindOfClass:[NSString class]]) signSecret = secret;
            }
        } @catch (NSException *e) {}
    }

    NSString *md5_1_input = [NSString stringWithFormat:@"%@%@%@%@", appId, @"magapp", fakeID, signSecret];
    newParts[5] = kn_md5(md5_1_input);

    // 重算 md5_2: MD5(MD5("magcloud") + udid + "mag_app_cloud" + appId + MD5("nanjingxinxi"))
    NSString *md5_2_input = [NSString stringWithFormat:@"%@%@%@%@%@",
        kn_md5(@"magcloud"), fakeID, @"mag_app_cloud", appId, kn_md5(@"nanjingxinxi")];
    newParts[6] = kn_md5(md5_2_input);

    NSString *newMagPart = [newParts componentsJoinedByString:@"|"];
    return [NSString stringWithFormat:@"%@%@", prefix, newMagPart];
}

#pragma mark - Hook NSMutableURLRequest setAllHTTPHeaderFields: 和 setValue:forHTTPHeaderField:

static void (*orig_setValue_forHTTPHeaderField)(id, SEL, NSString *, NSString *);
static void kn_setValue_forHTTPHeaderField(id self, SEL _cmd, NSString *value, NSString *field) {
    if ([field isEqualToString:@"User-Agent"] && value) {
        NSString *patched = kn_patchUserAgent(value);
        if (patched != value) {
            orig_setValue_forHTTPHeaderField(self, _cmd, patched, field);
            return;
        }
    }
    orig_setValue_forHTTPHeaderField(self, _cmd, value, field);
}

static void (*orig_setAllHTTPHeaderFields)(id, SEL, NSDictionary *);
static void kn_setAllHTTPHeaderFields(id self, SEL _cmd, NSDictionary *fields) {
    if (fields[@"User-Agent"]) {
        NSMutableDictionary *newFields = [fields mutableCopy];
        newFields[@"User-Agent"] = kn_patchUserAgent(fields[@"User-Agent"]);
        orig_setAllHTTPHeaderFields(self, _cmd, newFields);
        return;
    }
    orig_setAllHTTPHeaderFields(self, _cmd, fields);
}

// 也 hook addValue:forHTTPHeaderField:
static void (*orig_addValue_forHTTPHeaderField)(id, SEL, NSString *, NSString *);
static void kn_addValue_forHTTPHeaderField(id self, SEL _cmd, NSString *value, NSString *field) {
    if ([field isEqualToString:@"User-Agent"] && value) {
        NSString *patched = kn_patchUserAgent(value);
        if (patched != value) {
            orig_addValue_forHTTPHeaderField(self, _cmd, patched, field);
            return;
        }
    }
    orig_addValue_forHTTPHeaderField(self, _cmd, value, field);
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
    NSDictionary *delQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: key,
    };
    SecItemDelete((__bridge CFDictionaryRef)delQuery);
    NSDictionary *attrs = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
    };
    SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
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

#pragma mark - 友盟黑名单

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
        NSLog(@"[KN] ===== v7.0 init, fakeUDID=%@ =====", fakeID);

        // 1. 替换 Keychain（以防万一）
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

        // 3. 核心: hook NSMutableURLRequest 的 header 设置方法
        //    这是最底层的拦截，所有 HTTP 请求都要经过这里
        Class reqCls = [NSMutableURLRequest class];

        Method m1 = class_getInstanceMethod(reqCls, @selector(setValue:forHTTPHeaderField:));
        if (m1) {
            orig_setValue_forHTTPHeaderField = (void(*)(id, SEL, NSString*, NSString*))method_getImplementation(m1);
            method_setImplementation(m1, (IMP)kn_setValue_forHTTPHeaderField);
            NSLog(@"[KN] NSMutableURLRequest setValue:forHTTPHeaderField: hooked");
        }

        Method m2 = class_getInstanceMethod(reqCls, @selector(setAllHTTPHeaderFields:));
        if (m2) {
            orig_setAllHTTPHeaderFields = (void(*)(id, SEL, NSDictionary*))method_getImplementation(m2);
            method_setImplementation(m2, (IMP)kn_setAllHTTPHeaderFields);
            NSLog(@"[KN] NSMutableURLRequest setAllHTTPHeaderFields: hooked");
        }

        Method m3 = class_getInstanceMethod(reqCls, @selector(addValue:forHTTPHeaderField:));
        if (m3) {
            orig_addValue_forHTTPHeaderField = (void(*)(id, SEL, NSString*, NSString*))method_getImplementation(m3);
            method_setImplementation(m3, (IMP)kn_addValue_forHTTPHeaderField);
            NSLog(@"[KN] NSMutableURLRequest addValue:forHTTPHeaderField: hooked");
        }

        // 4. 网络拦截
        [NSURLProtocol registerClass:[KNDeviceProtocol class]];

        NSLog(@"[KN] ===== v7.0 request-level hooks installed =====");
    } @catch (NSException *e) {
        NSLog(@"[KN] init exception: %@", e);
    }

    // 5. 延迟 hook 友盟 filter（需要等类加载）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
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

            // DeviceUtil udid（双保险）
            Class deviceCls = objc_getClass("DeviceUtil");
            if (deviceCls) {
                Method m = class_getClassMethod(deviceCls, NSSelectorFromString(@"udid"));
                if (m) {
                    NSString *fid = kn_fakeUDID();
                    method_setImplementation(m, imp_implementationWithBlock(^NSString *(id s) { return fid; }));
                }
            }

            NSLog(@"[KN] v7.0 delayed hooks installed");
        } @catch (NSException *e) {
            NSLog(@"[KN] delayed hook exception: %@", e);
        }
    });
}
