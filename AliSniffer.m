// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (v10.1)
// 策略: 伪装 Android UA + bypass MAGRiskSDK
// 只 hook APP 自己的类，不碰系统类

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

static NSString *kn_androidUA(NSString *token) {
    NSString *appCode = @"kuniu";
    NSString *appSecret = @"nanjingxinxi";
    NSString *utdid = kn_fakeUDID();
    NSString *md5_1 = kn_md5([NSString stringWithFormat:@"%@magapp%@%@", appCode, utdid, appSecret]);
    NSString *md5_2 = kn_md5([NSString stringWithFormat:@"%@magapp%@nanjinglinyan", appCode, utdid]);
    NSString *tk = (token && token.length > 0) ? token : @"null";
    return [NSString stringWithFormat:
        @"MAGAPPX|6.4.0-6.4.3-218|Android 13 Samsung SM-G998B|%@|%@|%@|%@|%@",
        appCode, utdid, md5_1, md5_2, tk];
}

// ============================================================
// Hook 1: fetchUserAgent → Android UA
// 原始方法从 UserService 获取 token，我们也这样做
// ============================================================
static id (*orig_fetchUA)(id, SEL);
static id hook_fetchUA(id self, SEL _cmd) {
    NSString *token = nil;
    @try {
        Class userServiceCls = objc_getClass("UserService");
        if (userServiceCls) {
            id service = ((id (*)(id, SEL))objc_msgSend)(userServiceCls, NSSelectorFromString(@"service"));
            if (service) {
                id tk = ((id (*)(id, SEL))objc_msgSend)(service, NSSelectorFromString(@"userToken"));
                if (tk && [tk isKindOfClass:[NSString class]] && [(NSString *)tk length] > 0) {
                    token = tk;
                }
            }
        }
    } @catch (NSException *e) {
        NSLog(@"[KN] token fetch error: %@", e);
    }
    return kn_androidUA(token);
}

// ============================================================
// Hook 2: mag_fetchVersion → Android 版本号
// ============================================================
static id (*orig_fetchVersion)(id, SEL);
static id hook_fetchVersion(id self, SEL _cmd) {
    return @"Android-6.4.0-6.4.3-218";
}

// ============================================================
// Hook 3: MAGRiskSDK startWithConfigure:callback:
// 直接回调空 token，跳过顶象 SDK
// ============================================================
static void hook_startRisk(id self, SEL _cmd, id configure, id callback) {
    NSLog(@"[KN] MAGRiskSDK bypassed");
    if (callback) {
        void (^blk)(BOOL, id) = callback;
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                blk(NO, nil);
            } @catch (NSException *e) {
                NSLog(@"[KN] callback error: %@", e);
            }
        });
    }
}

// ============================================================
// 入口
// ============================================================
__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"[KN] v10.1 init, fakeUDID=%@", kn_fakeUDID());

            Class headerCls = objc_getClass("MAGApiRequestHeaderProvider");
            if (headerCls) {
                // fetchUserAgent (实例方法)
                Method m1 = class_getInstanceMethod(headerCls, NSSelectorFromString(@"fetchUserAgent"));
                if (m1) {
                    orig_fetchUA = (id(*)(id, SEL))method_getImplementation(m1);
                    method_setImplementation(m1, (IMP)hook_fetchUA);
                    NSLog(@"[KN] fetchUserAgent hooked");
                }

                // mag_fetchVersion (实例方法)
                Method m2 = class_getInstanceMethod(headerCls, NSSelectorFromString(@"mag_fetchVersion"));
                if (m2) {
                    orig_fetchVersion = (id(*)(id, SEL))method_getImplementation(m2);
                    method_setImplementation(m2, (IMP)hook_fetchVersion);
                    NSLog(@"[KN] mag_fetchVersion hooked");
                }
            }

            // MAGRiskSDK (类方法)
            Class riskCls = objc_getClass("MAGRiskSDK");
            if (riskCls) {
                Method m3 = class_getClassMethod(riskCls, NSSelectorFromString(@"startWithConfigure:callback:"));
                if (m3) {
                    method_setImplementation(m3, (IMP)hook_startRisk);
                    NSLog(@"[KN] MAGRiskSDK hooked");
                }
            }

            NSLog(@"[KN] v10.1 ready, UA=%@", kn_androidUA(@""));
        } @catch (NSException *e) {
            NSLog(@"[KN] init error: %@", e);
        }
    });
}
