// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (v9.0 Final)
// 策略: 伪装成 Android 设备，用 Web 工具验证过的 UA 格式
// 同时跳过 ac_token（Web 端不传也能播放）

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSString *kn_md5(NSString *input) {
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), digest);
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    return output;
}

// 持久化假设备 ID
static NSString *kn_fakeUDID(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    NSString *key = @"kn_v9_udid";
    cached = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (!cached || cached.length == 0) {
        // 生成类似 Android 设备 ID 的格式
        cached = [NSString stringWithFormat:@"KN%@", [[[NSUUID UUID] UUIDString] substringToIndex:16]];
        [[NSUserDefaults standardUserDefaults] setObject:cached forKey:key];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    return cached;
}

// 构建 Android 格式的 UA（和 Web 工具一样的格式）
static NSString *kn_buildAndroidUA(NSString *token) {
    NSString *appCode = @"kuniu";
    NSString *appSecret = @"nanjingxinxi";
    NSString *utdid = kn_fakeUDID();

    // Android 版 MD5 公式（从 Web 工具验证过）
    NSString *md5_1 = kn_md5([NSString stringWithFormat:@"%@%@%@%@", appCode, @"magapp", utdid, appSecret]);
    NSString *md5_2 = kn_md5([NSString stringWithFormat:@"%@%@%@%@", appCode, @"magapp", utdid, @"nanjinglinyan"]);

    NSString *tokenStr = (token && token.length > 0) ? token : @"null";

    // MAGAPPX|版本|系统|appCode|utdid|md5_1|md5_2|token
    return [NSString stringWithFormat:@"MAGAPPX|6.4.0-6.4.3-218|Android 13 Samsung SM-G998B|%@|%@|%@|%@|%@",
            appCode, utdid, md5_1, md5_2, tokenStr];
}

// ============================================================
// Hook: fetchUserAgent — 直接返回 Android 格式 UA
// ============================================================

static id (*orig_fetchUserAgent)(id, SEL);

static id hook_fetchUserAgent(id self, SEL _cmd) {
    // 获取当前 token
    NSString *token = nil;
    @try {
        Class userServiceCls = objc_getClass("UserService");
        if (userServiceCls) {
            id service = ((id (*)(id, SEL))objc_msgSend)(userServiceCls, NSSelectorFromString(@"service"));
            if (service) {
                token = ((id (*)(id, SEL))objc_msgSend)(service, NSSelectorFromString(@"userToken"));
            }
        }
    } @catch (NSException *e) {}

    NSString *ua = kn_buildAndroidUA(token);
    return ua;
}

// ============================================================
// Hook: NSMutableDictionary — 拦截 ac_token
// ============================================================

static void (*orig_setObj)(id, SEL, id, id);

static void hook_setObj(id self, SEL _cmd, id obj, id key) {
    if ([key isKindOfClass:[NSString class]] && [key isEqualToString:@"ac_token"]) {
        return; // 跳过 ac_token
    }
    orig_setObj(self, _cmd, obj, key);
}

// ============================================================
// 入口
// ============================================================

__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"[KN] v9.0 init, fakeUDID=%@", kn_fakeUDID());

            // Hook fetchUserAgent (实例方法)
            Class headerCls = objc_getClass("MAGApiRequestHeaderProvider");
            if (headerCls) {
                Method m = class_getInstanceMethod(headerCls, NSSelectorFromString(@"fetchUserAgent"));
                if (m) {
                    orig_fetchUserAgent = (id(*)(id, SEL))method_getImplementation(m);
                    method_setImplementation(m, (IMP)hook_fetchUserAgent);
                    NSLog(@"[KN] fetchUserAgent hooked");
                }
            }

            // Hook NSMutableDictionary 拦截 ac_token
            Method m2 = class_getInstanceMethod([NSMutableDictionary class], @selector(setObject:forKeyedSubscript:));
            if (m2) {
                orig_setObj = (void(*)(id, SEL, id, id))method_getImplementation(m2);
                method_setImplementation(m2, (IMP)hook_setObj);
                NSLog(@"[KN] ac_token intercept hooked");
            }

            NSLog(@"[KN] v9.0 done, UA=%@", kn_buildAndroidUA(@"test"));
        } @catch (NSException *e) {
            NSLog(@"[KN] exception: %@", e);
        }
    });
}
