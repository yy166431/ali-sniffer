// AliSniffer.m - 酷牛 v6.4.1 完整 Bypass (v11.2)
// 功能: 设备 ID 替换 + 风控 SDK 封杀 + 签名检测绕过 + 越狱检测绕过 + 调试检测绕过
// 只 hook APP 自己的类，不碰系统类

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
// 1. UA 设备 ID 替换
// ============================================================
static id (*orig_fetchUA)(id, SEL);
static id hook_fetchUA(id self, SEL _cmd) {
    NSString *origUA = orig_fetchUA(self, _cmd);
    if (!origUA || origUA.length == 0) return origUA;
    NSRange magRange = [origUA rangeOfString:@"MAGAPPX"];
    if (magRange.location == NSNotFound) return origUA;
    NSString *prefix = (magRange.location > 0) ? [origUA substringToIndex:magRange.location] : @"";
    NSString *magPart = [origUA substringFromIndex:magRange.location];
    NSArray *parts = [magPart componentsSeparatedByString:@"|"];
    if (parts.count < 5) return origUA;
    NSMutableArray *newParts = [parts mutableCopy];
    newParts[4] = kn_fakeUDID();
    return [NSString stringWithFormat:@"%@%@", prefix, [newParts componentsJoinedByString:@"|"]];
}

// ============================================================
// 2. MAGRiskSDK bypass — 直接回调空 token
// ============================================================
static void hook_startRisk(id self, SEL _cmd, id configure, id callback) {
    if (callback) {
        void (^blk)(BOOL, id) = callback;
        dispatch_async(dispatch_get_main_queue(), ^{
            @try { blk(NO, nil); } @catch (NSException *e) {}
        });
    }
}

// ============================================================
// 3. DeviceUtil udid → 假 ID
// ============================================================
static id hook_deviceUdid(id self, SEL _cmd) { return kn_fakeUDID(); }

// ============================================================
// 4. DXRiskManager — 完全封杀
// ============================================================
static BOOL hook_dxSetup(id self, SEL _cmd) { return NO; }
static id hook_dxGetToken(id self, SEL _cmd, id a, id b) { return @""; }
static id hook_dxSharedInstance(id self, SEL _cmd) { return nil; }

// ============================================================
// 5. DXKeyChainUtils — 禁止读写指纹
// ============================================================
static id hook_dxLoadKC(id self, SEL _cmd) { return nil; }
static void hook_dxSaveKC(id self, SEL _cmd, id d) {}
static void hook_dxSetKC(id self, SEL _cmd, id v, id k) {}
static id hook_dxGetKC(id self, SEL _cmd, id k, id def) { return def; }

// ============================================================
// 6. 签名检测绕过
// ============================================================
static void hook_checkSignAuth(id self, SEL _cmd, id a) {}
static void hook_processSaveAppSign(id self, SEL _cmd, id a) {}

// ============================================================
// 7. 越狱检测绕过
// ============================================================
static BOOL hook_returnNO(id self, SEL _cmd) { return NO; }
static NSString *hook_returnEmpty(id self, SEL _cmd) { return @""; }

// ============================================================
// 8. 调试检测绕过
// ============================================================
static BOOL hook_isBeingDebugged(id self, SEL _cmd) { return NO; }

// ============================================================
// 9. 友盟 Filter 绕过
// ============================================================
static void hook_initFilterConfig(id self, SEL _cmd) {}

// ============================================================
// 工具: 安全 hook 类方法
// ============================================================
static void hookClassMethod(const char *cls, const char *sel, IMP newIMP) {
    Class c = objc_getClass(cls);
    if (!c) return;
    Method m = class_getClassMethod(c, sel_registerName(sel));
    if (m) method_setImplementation(m, newIMP);
}

static void hookInstanceMethod(const char *cls, const char *sel, IMP newIMP) {
    Class c = objc_getClass(cls);
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel_registerName(sel));
    if (m) method_setImplementation(m, newIMP);
}

// ============================================================
// 入口
// ============================================================
__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"[KN] v11.2 init, fakeUDID=%@", kn_fakeUDID());

            // === 1. UA 设备 ID 替换 ===
            Class headerCls = objc_getClass("MAGApiRequestHeaderProvider");
            if (headerCls) {
                Method m = class_getInstanceMethod(headerCls, sel_registerName("fetchUserAgent"));
                if (m) {
                    orig_fetchUA = (id(*)(id, SEL))method_getImplementation(m);
                    method_setImplementation(m, (IMP)hook_fetchUA);
                }
            }

            // === 2. MAGRiskSDK bypass ===
            hookClassMethod("MAGRiskSDK", "startWithConfigure:callback:", (IMP)hook_startRisk);

            // === 3. DeviceUtil udid ===
            hookClassMethod("DeviceUtil", "udid", (IMP)hook_deviceUdid);

            // === 4. DXRiskManager 封杀 ===
            hookClassMethod("DXRiskManager", "setup", (IMP)hook_dxSetup);
            hookClassMethod("DXRiskManager", "getToken:extendsParams:", (IMP)hook_dxGetToken);
            hookClassMethod("DXRiskManager", "sharedInstance", (IMP)hook_dxSharedInstance);

            // === 5. DXKeyChainUtils 封杀 ===
            hookClassMethod("DXKeyChainUtils", "loadKeychainDict", (IMP)hook_dxLoadKC);
            hookClassMethod("DXKeyChainUtils", "saveKeychainDict:", (IMP)hook_dxSaveKC);
            hookClassMethod("DXKeyChainUtils", "set:forkey:", (IMP)hook_dxSetKC);
            hookClassMethod("DXKeyChainUtils", "get:default:", (IMP)hook_dxGetKC);

            // === 6. 签名检测绕过 ===
            hookClassMethod("OpenApi", "checkSignAuthIfNeed:", (IMP)hook_checkSignAuth);
            hookClassMethod("OpenApi", "processSaveAppSignInfo:", (IMP)hook_processSaveAppSign);

            // === 7. 越狱检测绕过 ===
            // SystemUtil
            hookClassMethod("SystemUtil", "isJailBroken", (IMP)hook_returnNO);
            // UMUtils
            hookClassMethod("UMUtils", "isDeviceJailBreak", (IMP)hook_returnNO);
            hookClassMethod("UMUtils", "deviceJailBreakString", (IMP)hook_returnEmpty);
            // UMCrashUtils
            hookClassMethod("UMCrashUtils", "getDeviceJailBreakString", (IMP)hook_returnEmpty);
            // MobClick
            hookClassMethod("MobClick", "isJailbroken", (IMP)hook_returnNO);
            // IFlySystemInfo
            hookClassMethod("IFlySystemInfo", "isJailbroken", (IMP)hook_returnNO);
            // GDTDeviceManager (实例方法)
            hookInstanceMethod("GDTDeviceManager", "isJailBroken", (IMP)hook_returnNO);
            // UIDevice (实例方法)
            hookInstanceMethod("UIDevice", "isJailbroken", (IMP)hook_returnNO);
            // UIDevice stee_isJailbreak_1~7 (实例方法)
            for (int i = 1; i <= 7; i++) {
                NSString *sel = [NSString stringWithFormat:@"stee_isJailbreak_%d", i];
                hookInstanceMethod("UIDevice", sel.UTF8String, (IMP)hook_returnNO);
            }
            // turing 越狱检测
            hookClassMethod("turing_3D6blckaNTWOgUNBC", "isBeingDebugged", (IMP)hook_isBeingDebugged);

            // === 8. 调试检测绕过 ===
            hookClassMethod("WPKOOMDetector", "isBeingDebugged", (IMP)hook_isBeingDebugged);

            // === 9. 友盟 Filter ===
            hookInstanceMethod("UMComFilterManager", "initFilterConfigAndVerify", (IMP)hook_initFilterConfig);

            NSLog(@"[KN] v11.2 ready — all protections disabled");
        } @catch (NSException *e) {
            NSLog(@"[KN] init error: %@", e);
        }
    });
}
