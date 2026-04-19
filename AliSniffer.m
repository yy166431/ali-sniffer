// AliSniffer.m - 酷牛 v6.4.1 设备封禁 Bypass (v11.0)
// 策略: 保持 iOS UA 格式，替换其中的设备 ID + bypass MAGRiskSDK
// 只 hook APP 自己的类

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSString *kn_fakeUDID(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    NSString *key = @"kn_v11_udid";
    cached = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (!cached || cached.length == 0) {
        cached = [[[NSUUID UUID] UUIDString] uppercaseString];
        [[NSUserDefaults standardUserDefaults] setObject:cached forKey:key];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    return cached;
}

// ============================================================
// Hook 1: fetchUserAgent
// 调用原始方法获取完整 UA 字符串，然后替换其中的设备 ID
// UA 格式: "...webViewUA MAGAPPX|ver|sys|appId|UDID|md5_1|md5_2|token"
// 或: "MAGAPPX|ver|sys|appId|UDID|md5_1|md5_2|token"
// 我们找到 MAGAPPX 部分，替换 [4] 位置的 UDID
// 不重算 MD5 — 服务端可能不验证 MD5，只看 UDID
// 如果不行再加 MD5 重算
// ============================================================
static id (*orig_fetchUA)(id, SEL);
static id hook_fetchUA(id self, SEL _cmd) {
    NSString *origUA = orig_fetchUA(self, _cmd);
    if (!origUA || origUA.length == 0) return origUA;

    // 找 MAGAPPX 的位置
    NSRange magRange = [origUA rangeOfString:@"MAGAPPX"];
    if (magRange.location == NSNotFound) return origUA;

    NSString *prefix = (magRange.location > 0) ? [origUA substringToIndex:magRange.location] : @"";
    NSString *magPart = [origUA substringFromIndex:magRange.location];

    NSArray *parts = [magPart componentsSeparatedByString:@"|"];
    if (parts.count < 5) return origUA;

    NSMutableArray *newParts = [parts mutableCopy];
    NSString *fakeID = kn_fakeUDID();

    // 替换 [4] = UDID
    newParts[4] = fakeID;

    // 重新拼接
    NSString *newMagPart = [newParts componentsJoinedByString:@"|"];
    NSString *newUA = [NSString stringWithFormat:@"%@%@", prefix, newMagPart];

    NSLog(@"[KN] UA patched, udid=%@", fakeID);
    return newUA;
}

// ============================================================
// Hook 2: MAGRiskSDK startWithConfigure:callback:
// 直接回调空 token，跳过顶象 SDK
// ============================================================
static void hook_startRisk(id self, SEL _cmd, id configure, id callback) {
    NSLog(@"[KN] MAGRiskSDK bypassed");
    if (callback) {
        void (^blk)(BOOL, id) = callback;
        dispatch_async(dispatch_get_main_queue(), ^{
            @try { blk(NO, nil); } @catch (NSException *e) {}
        });
    }
}

// ============================================================
// Hook 3: DeviceUtil udid → 返回假 ID（影响所有读取设备 ID 的地方）
// ============================================================
static id hook_deviceUdid(id self, SEL _cmd) {
    return kn_fakeUDID();
}

// ============================================================
// 入口
// ============================================================
__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"[KN] v11.0 init, fakeUDID=%@", kn_fakeUDID());

            // Hook fetchUserAgent (实例方法)
            Class headerCls = objc_getClass("MAGApiRequestHeaderProvider");
            if (headerCls) {
                Method m1 = class_getInstanceMethod(headerCls, NSSelectorFromString(@"fetchUserAgent"));
                if (m1) {
                    orig_fetchUA = (id(*)(id, SEL))method_getImplementation(m1);
                    method_setImplementation(m1, (IMP)hook_fetchUA);
                    NSLog(@"[KN] fetchUserAgent hooked");
                }
            }

            // Hook MAGRiskSDK (类方法)
            Class riskCls = objc_getClass("MAGRiskSDK");
            if (riskCls) {
                Method m2 = class_getClassMethod(riskCls, NSSelectorFromString(@"startWithConfigure:callback:"));
                if (m2) {
                    method_setImplementation(m2, (IMP)hook_startRisk);
                    NSLog(@"[KN] MAGRiskSDK hooked");
                }
            }

            // Hook DeviceUtil udid (类方法)
            Class deviceCls = objc_getClass("DeviceUtil");
            if (deviceCls) {
                Method m3 = class_getClassMethod(deviceCls, NSSelectorFromString(@"udid"));
                if (m3) {
                    method_setImplementation(m3, (IMP)hook_deviceUdid);
                    NSLog(@"[KN] DeviceUtil udid hooked");
                }
            }

            NSLog(@"[KN] v11.0 ready");
        } @catch (NSException *e) {
            NSLog(@"[KN] init error: %@", e);
        }
    });
}
