// AliSniffer.m — iOS14/15 全功能 + iOS16 安全版
// 原有功能完整保留：抓到 URL → 弹窗 + 复制
// 新增功能：自动上传到 http://139.155.57.242:8088/api/append，带 Token，失败缓存+定时重试

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

// ====== 静默宏（默认不输出控制台）======
#ifndef ENABLE_DEBUG_LOG
#define LOG(...)
#else
#define LOG(...) NSLog(__VA_ARGS__)
#endif

// ====== 弹窗开关（1=命中时弹窗+复制，0=完全静默仅复制）======
#ifndef SNIFFER_ENABLE_POPUP
#define SNIFFER_ENABLE_POPUP 1
#endif

// ====== iOS16 安全策略（为避免崩溃，默认关闭这些模块；如你验证安全可改为 1）======
#ifndef SNIFFER_IOS16_ENABLE_NSURLPROTOCOL
#define SNIFFER_IOS16_ENABLE_NSURLPROTOCOL 0
#endif
#ifndef SNIFFER_IOS16_ENABLE_CFREADSTREAM
#define SNIFFER_IOS16_ENABLE_CFREADSTREAM 0
#endif
#ifndef SNIFFER_IOS16_ENABLE_LIBCURL
#define SNIFFER_IOS16_ENABLE_LIBCURL 0
#endif

// ====== 上传相关配置 ======
static NSMutableSet<NSString *> *uploadedSet;
static NSMutableSet<NSString *> *cacheSet;
static NSString * const kAppendAPI  = @"http://139.155.57.242:8088/api/append";
static NSString * const kAdminToken = @"xZ7vN3qJc4G8f2K0bYw1sQp9LrT6D5aR";

static void UploadURL(NSString *line) {
    if (!line.length) return;
    if (!uploadedSet) uploadedSet = [NSMutableSet set];
    if ([uploadedSet containsObject:line]) return; // 去重
    [uploadedSet addObject:line];

    NSURL *url = [NSURL URLWithString:kAppendAPI];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:kAdminToken forHTTPHeaderField:@"X-Token"];

    NSDictionary *body = @{@"line": line};
    NSData *data = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    req.HTTPBody = data;

    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (e) {
            NSLog(@"[AliSniffer] upload failed: %@ -> %@", line, e);
            if (!cacheSet) cacheSet = [NSMutableSet set];
            [cacheSet addObject:line];
        } else {
            NSLog(@"[AliSniffer] upload ok: %@", line);
        }
    }] resume];
}

static void FlushCache() {
    if (!cacheSet.count) return;
    NSSet *copy = [cacheSet copy];
    [cacheSet removeAllObjects];
    for (NSString *s in copy) UploadURL(s);
}

// ====== 噪声/白名单 ======
static NSArray<NSString *> *BlockedSubstrings(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"log.aliyuncs.com/logstores", @"/beacon", @"/monitor", @"/ums", @"/umeng",
            @"/collect", @"bugly", @"crash", @"analytics", @"sentry"
        ];
    });
    return a;
}
static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            @"knyb.kuniunet.com",
            @"knydb.kuniunet.com",
            @"qiaohongb.kuniunet.com",
            @"v2.weizan.cn"
        ];
    });
    return a;
}

// ====== 工具 ======
static inline NSString *HostOfURLString(NSString *s) {
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.lowercaseString ?: @"";
}
static inline BOOL IsNoise(NSString *lower) {
    for (NSString *k in BlockedSubstrings()) if ([lower containsString:k]) return YES;
    return NO;
}
static inline BOOL IsPlayable(NSString *u) {
    if (u.length == 0) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@"m3u8"] ||
        [s containsString:@".mp4"] ||
        [s containsString:@".flv"] ||
        [s hasPrefix:@"rtmp://"] || [s hasPrefix:@"rtmps://"] ||
        (([s hasPrefix:@"ws://"] || [s hasPrefix:@"wss://"]) && [s containsString:@".flv"])) {
        return YES;
    }
    NSString *h = HostOfURLString(s);
    for (NSString *w in WhitelistedHosts()) if ([h hasSuffix:w]) return YES;
    return NO;
}
// 10s 去重
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static inline BOOL SeenRecently(NSString *k, NSTimeInterval sec) {
    static dispatch_once_t once; dispatch_once(&once, ^{ g_seen = [NSMutableDictionary dictionary]; });
    NSDate *now = [NSDate date]; NSDate *last = g_seen[k];
    if (last && [now timeIntervalSinceDate:last] < sec) return YES;
    g_seen[k] = now; if (g_seen.count > 256) [g_seen removeAllObjects]; return NO;
}
static inline void ShowPopupIfNeeded(NSString *title, NSString *msg) {
#if SNIFFER_ENABLE_POPUP
    if (!msg.length) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = msg;
        }]];
        [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        if (vc) [vc presentViewController:a animated:YES completion:nil];
    });
#else
    (void)title;
    if (msg.length) [UIPasteboard generalPasteboard].string = msg;
#endif
}
static inline void ReportURL(NSString *url) {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;
    if (IsNoise(lower)) return;
    if (!IsPlayable(lower)) return;
    if (SeenRecently(url, 10.0)) return;

    if ([lower containsString:@"m3u8"]) {
        ShowPopupIfNeeded(@"抓到 M3U8", url);
    } else if ([lower containsString:@".mp4"]) {
        ShowPopupIfNeeded(@"抓到 MP4", url);
    } else if ([lower containsString:@".flv"] ||
               [lower hasPrefix:@"rtmp://"] || [lower hasPrefix:@"rtmps://"] ||
               (([lower hasPrefix:@"ws://"] || [lower hasPrefix:@"wss://"]) && [lower containsString:@".flv"])) {
        ShowPopupIfNeeded(@"抓到直播流 (FLV/RTMP)", url);
    } else {
        ShowPopupIfNeeded(@"命中可疑播放 URL", url);
    }

    // === 新增：自动上传 ===
    UploadURL(url);
}
static inline NSString *ToURLString(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:NSString.class]) return obj;
    if ([obj isKindOfClass:NSURL.class])    return [(NSURL *)obj absoluteString];
    @try {
        id v = [obj respondsToSelector:@selector(URL)] ? [obj performSelector:@selector(URL)] : nil;
        if (!v && [obj respondsToSelector:@selector(url)]) v = [obj performSelector:@selector(url)];
        if ([v isKindOfClass:NSString.class]) return v;
        if ([v isKindOfClass:NSURL.class])    return [(NSURL *)v absoluteString];
    } @catch (...) {}
    return nil;
}
static inline void Swz(Class c, SEL sel, IMP newImp, IMP *origStore) {
    if (!c || !sel || !newImp) return;
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    if (origStore) *origStore = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

// ====== 1) NSURLSessionTask.resume ======
// （保留原有实现……）

// ====== 2) NSURLProtocol（iOS14/15 默认启用，iOS16 默认关闭）
// （保留原有实现……）

// ====== 3) CFReadStream
// （保留原有实现……）

// ====== 4) AVPlayer / AVURLAsset
// （保留原有实现……）

// ====== 5) WKWebView 注入
// （保留原有实现……）

// ====== 6) libcurl
// （保留原有实现……）

// ====== 安装 Hook ======
__attribute__((constructor))
static void _sniffer_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            // 保留你原有的 Hook 安装逻辑……

            // === 新增：启动定时器，每小时兜底上传缓存 ===
            [NSTimer scheduledTimerWithTimeInterval:3600
                                             repeats:YES
                                               block:^(NSTimer * _Nonnull t) {
                FlushCache();
            }];
            NSLog(@"[AliSniffer] 初始化完成，已启用自动上传 + 定时兜底");
        });
    }
}
