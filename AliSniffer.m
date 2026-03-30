// AliSniffer.m - 酷牛 设备黑名单/签名/越狱检测 Bypass
// 注入方式: 轻松签 dylib 注入 (非越狱)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include "fishhook.h"

#pragma mark - 工具宏

#define KN_SWIZZLE_INSTANCE(cls, origSel, newSel) \
do { \
    Method orig = class_getInstanceMethod(cls, origSel); \
    Method new  = class_getInstanceMethod(cls, newSel);  \
    if (orig && new) method_exchangeImplementations(orig, new); \
} while(0)

#define KN_SWIZZLE_CLASS(cls, origSel, newSel) \
do { \
    Method orig = class_getClassMethod(cls, origSel); \
    Method new  = class_getClassMethod(cls, newSel);  \
    if (orig && new) method_exchangeImplementations(orig, new); \
} while(0)

// 遍历所有类，对含有指定方法的类批量 hook
static void hookAllClassesWithSelector(SEL origSel, SEL newSel, BOOL isClassMethod) {
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    for (unsigned int i = 0; i < count; i++) {
        Class cls = classes[i];
        Method m = isClassMethod
            ? class_getClassMethod(cls, origSel)
            : class_getInstanceMethod(cls, origSel);
        if (!m) continue;
        Method newM = isClassMethod
            ? class_getClassMethod(cls, newSel)
            : class_getInstanceMethod(cls, newSel);
        if (newM) method_exchangeImplementations(m, newM);
    }
    free(classes);
}

#pragma mark - NSURLProtocol 拦截 checkDeviceStatus

@interface KNDeviceStatusProtocol : NSURLProtocol
@end

@implementation KNDeviceStatusProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *url = request.URL.absoluteString;
    if ([url containsString:@"checkDeviceStatus"]) {
        // 防止重复拦截
        if ([NSURLProtocol propertyForKey:@"KNHandled" inRequest:request]) return NO;
        return YES;
    }
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    // 构造一个"设备正常"的假响应
    // 通用结构: {"code":200,"msg":"success","data":{"isBlack":0,"status":1}}
    NSDictionary *fakeData = @{
        @"code": @200,
        @"msg": @"success",
        @"data": @{
            @"isBlack": @0,
            @"is_black": @0,
            @"status": @1,
            @"deviceStatus": @1,
            @"banned": @0,
            @"isBanned": @0,
            @"black": @0,
        }
    };
    NSData *body = [NSJSONSerialization dataWithJSONObject:fakeData options:0 error:nil];
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc]
        initWithURL:self.request.URL
         statusCode:200
        HTTPVersion:@"HTTP/1.1"
       headerFields:@{@"Content-Type": @"application/json"}];

    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:body];
    [self.client URLProtocolDidFinishLoading:self];
}

- (void)stopLoading {}

@end

#pragma mark - 模型层: setIsBlack: 强制 NO

// 用于替换所有含 setIsBlack: 的类
@interface NSObject (KNBlackBypass)
- (void)kn_setIsBlack:(BOOL)black;
- (BOOL)kn_isBlack;
@end

@implementation NSObject (KNBlackBypass)

- (void)kn_setIsBlack:(BOOL)black {
    // 强制传 NO，不管服务端返回什么
    [self kn_setIsBlack:NO];
}

- (BOOL)kn_isBlack {
    return NO;
}

@end

#pragma mark - 越狱检测 Bypass

@interface NSObject (KNJailbreakBypass)
- (BOOL)kn_isDeviceJailBreak;
- (NSString *)kn_getDeviceJailBreakString;
- (NSString *)kn_deviceJailBreakString;
@end

@implementation NSObject (KNJailbreakBypass)

- (BOOL)kn_isDeviceJailBreak {
    return NO;
}

- (NSString *)kn_getDeviceJailBreakString {
    return @"";
}

- (NSString *)kn_deviceJailBreakString {
    return @"";
}

@end

// stee_isJailbreak_1..7 — 这些是 ObjC 方法，类名未知，用遍历方式 hook
@interface NSObject (KNSteeJailbreak)
- (BOOL)kn_stee_isJailbreak_stub;
@end

@implementation NSObject (KNSteeJailbreak)
- (BOOL)kn_stee_isJailbreak_stub { return NO; }
@end

#pragma mark - 调试检测 Bypass (WPK)

@interface NSObject (KNDebugBypass)
+ (BOOL)kn_isBeingDebugged;
@end

@implementation NSObject (KNDebugBypass)
+ (BOOL)kn_isBeingDebugged { return NO; }
@end

#pragma mark - 签名检测 Bypass

@interface NSObject (KNSignBypass)
- (void)kn_checkSignAuthIfNeed:(id)arg;
- (void)kn_initFilterConfigAndVerify;
- (void)kn_processSaveAppSignInfo:(id)arg;
@end

@implementation NSObject (KNSignBypass)

- (void)kn_checkSignAuthIfNeed:(id)arg {
    // 直接跳过签名校验
}

- (void)kn_initFilterConfigAndVerify {
    // 跳过初始化时的签名验证
}

- (void)kn_processSaveAppSignInfo:(id)arg {
    // 跳过保存签名信息
}

@end

#pragma mark - 初始化入口

static void kn_setup(void) {
    // 1. 注册网络拦截
    [NSURLProtocol registerClass:[KNDeviceStatusProtocol class]];

    // 2. 遍历 hook setIsBlack: / isBlack
    hookAllClassesWithSelector(
        @selector(setIsBlack:), @selector(kn_setIsBlack:), NO);
    hookAllClassesWithSelector(
        @selector(isBlack), @selector(kn_isBlack), NO);

    // 3. 越狱检测
    hookAllClassesWithSelector(
        @selector(isDeviceJailBreak), @selector(kn_isDeviceJailBreak), NO);
    hookAllClassesWithSelector(
        @selector(getDeviceJailBreakString), @selector(kn_getDeviceJailBreakString), NO);
    hookAllClassesWithSelector(
        @selector(deviceJailBreakString), @selector(kn_deviceJailBreakString), NO);

    // stee_isJailbreak_1..7
    NSArray *steeSelNames = @[
        @"stee_isJailbreak_1", @"stee_isJailbreak_2", @"stee_isJailbreak_3",
        @"stee_isJailbreak_4", @"stee_isJailbreak_5", @"stee_isJailbreak_6",
        @"stee_isJailbreak_7"
    ];
    for (NSString *selName in steeSelNames) {
        hookAllClassesWithSelector(
            NSSelectorFromString(selName),
            @selector(kn_stee_isJailbreak_stub),
            NO);
    }

    // 4. WPK 调试检测
    Class wpkClass = objc_getClass("WPKOOMDetector");
    if (wpkClass) {
        KN_SWIZZLE_CLASS(wpkClass,
            @selector(isBeingDebugged),
            @selector(kn_isBeingDebugged));
    }

    // 5. 签名检测
    hookAllClassesWithSelector(
        @selector(checkSignAuthIfNeed:), @selector(kn_checkSignAuthIfNeed:), NO);
    hookAllClassesWithSelector(
        @selector(initFilterConfigAndVerify), @selector(kn_initFilterConfigAndVerify), NO);
    hookAllClassesWithSelector(
        @selector(processSaveAppSignInfo:), @selector(kn_processSaveAppSignInfo:), NO);
}

// dylib 加载时自动执行
__attribute__((constructor))
static void kn_init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        kn_setup();
        NSLog(@"[KN] Hooks installed.");
    });
}
