// AliSniffer_debug_uploader.m
// 诊断上传版：不 hook、不改 App 行为
// 作用：枚举运行时类名（Ali/AVP/AVPlayer/WKWebView/NSURLSession 等关键词）
//      -> 组合为纯文本 -> 以 text/plain 发送到服务器（带 X-Token）
//      -> 真机弹窗提示“已注入 / 已上传”
//
// 构建：clang ... -dynamiclib -framework UIKit -framework Foundation

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#pragma mark - 配置
static NSString * const PUSH_ENDPOINT = @"http://139.155.57.242:8088/api/push_raw"; // 你的接收地址（纯文本）
static NSString * const PUSH_TOKEN    = @"@Yy166431";                       // 令牌

/// 单次上传体积过大可能被服务器/网关截断；拆成 50KB 一段（可按需调大/调小）
static const NSUInteger kChunkBytes = 50 * 1024;

#pragma mark - 小工具

static inline void run_main(void (^blk)(void)) {
    if (!blk) return;
    if ([NSThread isMainThread]) blk();
    else dispatch_async(dispatch_get_main_queue(), blk);
}

static void popup(NSString *title, NSString *msg) {
    run_main(^{
        @try {
            UIWindow *keyWindow = nil;
            if (@available(iOS 13.0, *)) {
                for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if (scene.activationState == UISceneActivationStateForegroundActive) {
                        for (UIWindow *w in scene.windows) { if (w.isKeyWindow) { keyWindow = w; break; } }
                        if (keyWindow) break;
                    }
                }
            } else {
                keyWindow = [UIApplication sharedApplication].keyWindow;
            }
            if (!keyWindow) keyWindow = [UIApplication sharedApplication].windows.firstObject;
            UIViewController *root = keyWindow.rootViewController;
            while (root.presentedViewController) root = root.presentedViewController;
            if (!root) return;

            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title
                                                                        message:msg
                                                                 preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [root presentViewController:ac animated:YES completion:nil];
        } @catch (__unused NSException *e) { /* 忽略 UI 异常 */ }
    });
}

static NSString *appInfoLine(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"(unknown-bid)";
    NSString *ver = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"?";
    NSString *build = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"?";
    NSString *model = [UIDevice currentDevice].model ?: @"?";
    NSString *sysver = [UIDevice currentDevice].systemVersion ?: @"?";
    return [NSString stringWithFormat:@"bundle=%@ version=%@(%@) device=%@ iOS=%@", bid, ver, build, model, sysver];
}

static void postPlainText(NSString *text, void (^done)(BOOL)) {
    if (!text) { if (done) done(NO); return; }
    NSURL *url = [NSURL URLWithString:PUSH_ENDPOINT];
    if (!url) { if (done) done(NO); return; }

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:PUSH_TOKEN forHTTPHeaderField:@"X-Token"];
    [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [text dataUsingEncoding:NSUTF8StringEncoding];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
                                     completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        BOOL ok = (!e && [r isKindOfClass:[NSHTTPURLResponse class]] &&
                   ((NSHTTPURLResponse*)r).statusCode >= 200 &&
                   ((NSHTTPURLResponse*)r).statusCode < 300);
        if (done) done(ok);
    }] resume];
}

static void postInChunks(NSString *allText, void (^finalDone)(BOOL)) {
    NSData *data = [allText dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) { if (finalDone) finalDone(NO); return; }
    NSUInteger total = data.length;
    if (total <= kChunkBytes) {
        postPlainText(allText, finalDone);
        return;
    }
    // 分片上传：每片加上 [part i/N] 前缀，服务端可按顺序拼接
    __block BOOL overallOK = YES;
    __block NSUInteger offset = 0;
    __block NSUInteger index = 0;
    NSUInteger parts = (total + kChunkBytes - 1) / kChunkBytes;

    void (^sendNext)(void) = ^{
        if (offset >= total) {
            if (finalDone) finalDone(overallOK);
            return;
        }
        NSUInteger len = MIN(kChunkBytes, total - offset);
        NSData *chunk = [data subdataWithRange:NSMakeRange(offset, len)];
        NSString *chunkStr = [[NSString alloc] initWithData:chunk encoding:NSUTF8StringEncoding];
        index++;
        NSString *header = [NSString stringWithFormat:@"[alisniffer_debug part %lu/%lu]\n", (unsigned long)index, (unsigned long)parts];
        postPlainText([header stringByAppendingString:(chunkStr ?: @"")], ^(BOOL ok){
            overallOK = overallOK && ok;
            offset += len;
            sendNext();
        });
    };
    sendNext();
}

#pragma mark - 枚举类并上传

static NSString *collectRuntimeReport(void) {
    NSMutableArray<NSString *> *hits = [NSMutableArray array];
    unsigned int n = 0;
    Class *classes = objc_copyClassList(&n);
    if (classes) {
        NSArray *keys = @[@"Ali", @"AVP", @"Aliyun", @"AliPlayer", @"UrlSource",
                          @"AVPlayer", @"AVURLAsset", @"AVPlayerItem",
                          @"WKWebView", @"WebKit", @"NSURLSession",
                          @"CFNetwork", @"Live", @"Stream", @"m3u8", @"rtmp", @"flv"];
        for (unsigned int i=0; i<n; i++) {
            const char *nm = class_getName(classes[i]);
            if (!nm) continue;
            NSString *name = [NSString stringWithUTF8String:nm];
            for (NSString *k in keys) {
                if ([name rangeOfString:k options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    [hits addObject:name];
                    break;
                }
            }
        }
        free(classes);
    }
    // 去重 + 排序
    NSArray *uniq = [NSOrderedSet orderedSetWithArray:hits].array;
    NSArray *sorted = [uniq sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];

    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"[alisniffer_debug start] %@\n", [NSDate date]];
    [out appendFormat:@"%@\n\n", appInfoLine()];
    [out appendFormat:@"found-candidate-classes=%lu\n\n", (unsigned long)sorted.count];

    NSUInteger showN = MIN((NSUInteger)80, sorted.count);
    [out appendString:@"--- first-matches ---\n"];
    for (NSUInteger i=0;i<showN;i++) {
        [out appendFormat:@"%lu: %@\n", (unsigned long)(i+1), sorted[i]];
    }
    [out appendString:@"\n--- full-list ---\n"];
    for (NSString *s in sorted) [out appendFormat:@"%@\n", s];
    [out appendString:@"\n[alisniffer_debug end]\n"];
    return out;
}

#pragma mark - 入口：注入后自动执行

__attribute__((constructor))
static void alisniffer_debug_bootstrap(void) {
    // 弹窗：已注入
    popup(@"AliSniffer (debug)", @"诊断版已注入：开始枚举类并上传…");

    // 稍微晚一点，避免和首屏动画抢 UI/线程
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        @try {
            NSString *report = collectRuntimeReport();
            postInChunks(report, ^(BOOL ok){
                popup(@"AliSniffer (debug)", ok ? @"已上传运行时类列表（到服务器）" : @"上传失败");
            });
        } @catch (__unused NSException *e) {
            popup(@"AliSniffer (debug)", @"枚举/上传异常");
        }
    });
}
