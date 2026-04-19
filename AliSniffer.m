// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (v10.0)
// 策略: 伪装 Android UA + hook MAGRiskSDK 返回空 token
// 不 hook 任何系统类，只 hook APP 自己的类

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

static NSString *kn_fakeUDID(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    NSString *key = @"kn_v10_udid";
    cached = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (!cached || cached.length == 0) {
        cached = [NSString stringWithFormat:@"KN%@",
            [[[NSUUID UUID] UUIDString] stringByReplacingOccurrencesOfString:@"-" withString:@""]];
        [[NSUserDefaults standardUserDefaults] setObject:cached forKey:key];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    return cached;
}

// Android 格式 UA（和 Web 工具一样）
static NSString *kn_androidUA(NSString *token) {
    NSString *appCode = @"kuniu";
    NSString *appSecret = @"nanjingxinxi";
    NSString *utdid = kn_fakeUDID();
    NSString *md5_1 = kn_md5([NSString stringWithFormat:@"%@magapp%@%@", appCode, utdid, appSecret]);
    NSString *md5_2 = kn_md5([NSString stringWithFormat:@"%@magapp%@nanjinglinyan", appCode, utdid]);
    NSString *tk = (token.length > 0) ? token : @"null";
    return [NSString stringWithFormat:
        @"MAGAPPX|6.4.0-6.4.3-218|Android 13 Samsung SM-G998B|%@|%@|%@|%@|%@",
        appCode, utdid, md5_1, md5_2, tk];
}

// ============================================================
// Hook 1: fetchUserAgent → Android UA
// ============================================================
static id (*orig_fetchUA)(id, SEL);
static id hook_fetchUA(id self, SEL _cmd) {
    NSString *token = nil;
    @try {
        token = ((id (*)(id, SEL))objc_msgSend)(self, NSSelectorFromString(@"userToken"));
    } @catch (NSException *e) {}
    return kn_androidUA(token);
}

// ============================================================
// Hook 2: MAGRiskSDK startWithConfigure:callback:
// 原始: 调用顶象 DXRisk SDK 获取设备指纹 token，然后回调
// Hook: 直接回调，传空 token，跳过顶象 SDK
//
// callback 签名: void(^)(BOOL setupResult, NSString *token)
// 传 (NO, nil) → callback 中 token.length == 0 → 不设置 ac_token
// ============================================================
static void (*orig_startRisk)(id, SEL, id, id);
static void hook_startRisk(id self, SEL _cmd, id configure, id callback) {
    NSLog(@"[KN] MAGRiskSDK intercepted, calling callback with nil token");
    if (callback) {
        // callback block: void(^)(BOOL, NSString*)
        void (^blk)(BOOL, id) = callback;
        // 在主线程回调（和原始行为一致）
        dispatch_async(dispatch_get_main_queue(), ^{
            blk(NO, nil);
        });
    }
}

// ============================================================
// Hook 3: mag-version header 也改成 Android 格式
// ============================================================
static id (*orig_magVersion)(id, SEL);
static id hook_magVersion(id self, SEL _cmd) {
    return @"Android-6.4.0-6.4.3-218";
}

// ============================================================
// 入口
// ============================================================
__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"[KN] v10.0 init, fakeUDID=%@", kn_fakeUDID());

            // Hook 1: fetchUserAgent
            Class headerCls = objc_getClass("MAGApiRequestHeaderProvider");
            if (headerCls) {
                Method m = class_getInstanceMethod(headerCls, NSSelectorFromString(@"fetchUserAgent"));
                if (m) {
                    orig_fetchUA = (id(*)(id, SEL))method_getImplementation(m);
                    method_setImplementation(m, (IMP)hook_fetchUA);
                    NSLog(@"[KN] fetchUserAgent → Android UA");
                }

                // 也 hook mag_version
                Method mv = class_getClassMethod(headerCls, NSSelectorFromString(@"mag_version"));
                if (mv) {
                    orig_magVersion = (id(*)(id, SEL))method_getImplementation(mv);
                    method_setImplementation(mv, (IMP)hook_magVersion);
                    NSLog(@"[KN] mag_version → Android");
                }
            }

            // Hook 2: MAGRiskSDK startWithConfigure:callback:
            Class riskCls = objc_getClass("MAGRiskSDK");
            if (riskCls) {
                Method m = class_getClassMethod(riskCls, NSSelectorFromString(@"startWithConfigure:callback:"));
                if (m) {
                    orig_startRisk = (void(*)(id, SEL, id, id))method_getImplementation(m);
                    method_setImplementation(m, (IMP)hook_startRisk);
                    NSLog(@"[KN] MAGRiskSDK → bypass");
                }
            }

            NSLog(@"[KN] v10.0 done");
            NSLog(@"[KN] UA: %@", kn_androidUA(@"test"));
        } @catch (NSException *e) {
            NSLog(@"[KN] exception: %@", e);
        }
    });
}
