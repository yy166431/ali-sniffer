// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (v8.0 Final)
// 基于完整 IDA 逆向 + Web 端验证
// 只做两件事: 1. 替换 UA 中的设备 ID  2. 跳过 ac_token

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

// 持久化假 UUID（存 NSUserDefaults，删 APP 就重置）
static NSString *kn_fakeUDID(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    NSString *key = @"kn_v8_udid";
    cached = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (!cached || cached.length == 0) {
        cached = [[[NSUUID UUID] UUIDString] uppercaseString];
        [[NSUserDefaults standardUserDefaults] setObject:cached forKey:key];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    return cached;
}

// ============================================================
// Hook 1: 替换 UA 中的设备 ID
// +[MAGApiRequestHeaderProvider userAgentWithoutTokenValues]
// 返回数组: [MAGAPPX, 版本, 系统, appId, udid, md5_1, md5_2]
// 替换 [4]=udid, 重算 [5] 和 [6]
// ============================================================

static id (*orig_uaValues)(id, SEL);

static id hook_uaValues(id self, SEL _cmd) {
    id origArray = orig_uaValues(self, _cmd);
    if (!origArray) return origArray;

    NSMutableArray *arr = [origArray mutableCopy];
    if (arr.count < 7) return origArray;

    NSString *fakeID = kn_fakeUDID();
    NSString *appId = arr[3];

    // 获取 signSecret
    NSString *signSecret = @"";
    @try {
        Class appConfigCls = objc_getClass("AppConfig");
        if (appConfigCls) {
            id config = ((id (*)(id, SEL))objc_msgSend)(appConfigCls, NSSelectorFromString(@"config"));
            if (config) {
                id secret = ((id (*)(id, SEL))objc_msgSend)(config, NSSelectorFromString(@"signSecret"));
                if (secret && [secret isKindOfClass:[NSString class]]) signSecret = secret;
            }
        }
    } @catch (NSException *e) {}

    // 替换 udid
    arr[4] = fakeID;
    // 重算 md5_1
    arr[5] = kn_md5([NSString stringWithFormat:@"%@%@%@%@", appId, @"magapp", fakeID, signSecret]);
    // 重算 md5_2
    arr[6] = kn_md5([NSString stringWithFormat:@"%@%@%@%@%@",
        kn_md5(@"magcloud"), fakeID, @"mag_app_cloud", appId, kn_md5(@"nanjingxinxi")]);

    return [arr copy];
}

// ============================================================
// Hook 2: 跳过 ac_token
// 在 requestVideoContent 的 callback 中，token 参数 (a3) 传给
// video_content_view API 的 "ac_token" 字段
// 我们 hook NSMutableDictionary setObject:forKeyedSubscript:
// 当 key 是 "ac_token" 时，不设置
// ============================================================

static void (*orig_setObject)(id, SEL, id, id);

static void hook_setObject(id self, SEL _cmd, id obj, id key) {
    if ([key isKindOfClass:[NSString class]] && [key isEqualToString:@"ac_token"]) {
        // 跳过 ac_token，不传给服务端
        return;
    }
    orig_setObject(self, _cmd, obj, key);
}

// ============================================================
// 入口
// ============================================================

__attribute__((constructor))
static void kn_init(void) {
    // 延迟 0.1 秒等类加载
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"[KN] v8.0 init, fakeUDID=%@", kn_fakeUDID());

            // Hook 1: userAgentWithoutTokenValues
            Class headerCls = objc_getClass("MAGApiRequestHeaderProvider");
            if (headerCls) {
                Method m = class_getClassMethod(headerCls, NSSelectorFromString(@"userAgentWithoutTokenValues"));
                if (m) {
                    orig_uaValues = (id(*)(id, SEL))method_getImplementation(m);
                    method_setImplementation(m, (IMP)hook_uaValues);
                    NSLog(@"[KN] UA hook OK");
                } else {
                    NSLog(@"[KN] UA method not found!");
                }
            } else {
                NSLog(@"[KN] MAGApiRequestHeaderProvider not found!");
            }

            // Hook 2: NSMutableDictionary setObject:forKeyedSubscript:
            // 拦截 ac_token 的设置
            Method m2 = class_getInstanceMethod([NSMutableDictionary class], @selector(setObject:forKeyedSubscript:));
            if (m2) {
                orig_setObject = (void(*)(id, SEL, id, id))method_getImplementation(m2);
                method_setImplementation(m2, (IMP)hook_setObject);
                NSLog(@"[KN] ac_token intercept OK");
            }

            NSLog(@"[KN] v8.0 done");
        } @catch (NSException *e) {
            NSLog(@"[KN] exception: %@", e);
        }
    });
}
