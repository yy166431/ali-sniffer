// AliSniffer.m —— 阿里云播放器直链嗅探 v2（更全入口 + 更强 NSURLSession 兜底）
// 只打印/复制 URL，不改变播放行为。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

#pragma mark - Util

static void _copyIfUseful(NSString *u) {
    if (u.length == 0) return;
    NSString *low = u.lowercaseString;
    // 优先复制 m3u8/mpd/flv；其余 http(s) 也打印出来
    if ([low containsString:@"m3u8"] || [low containsString:@".mpd"] || [low containsString:@".flv"] || [low containsString:@"playlist"]) {
        @try { [UIPasteboard generalPasteboard].string = u; } @catch (...) {}
        NSLog(@"[AliSniffer] copied: %@", u);
    }
}

static void _reportURLString(NSString *u, NSString *from) {
    if (u.length == 0) return;
    NSLog(@"[AliSniffer] URL (%@): %@", from, u);
    _copyIfUseful(u);
}

static NSString * _extractURLStringFromObj(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:[NSString class]]) return (NSString *)obj;
    if ([obj isKindOfClass:[NSURL class]]) return [(NSURL *)obj absoluteString];

    // 常见 AVPUrlSource: URL(NSURL*) / url(NSString*) / urlString(NSString*)
    @try {
        id v = nil;
        if ([obj respondsToSelector:@selector(URL)]) {
            v = [obj performSelector:@selector(URL)];
            if ([v isKindOfClass:[NSURL class]]) return [(NSURL *)v absoluteString];
            if ([v isKindOfClass:[NSString class]]) return (NSString *)v;
        }
        if ([obj respondsToSelector:@selector(url)]) {
            v = [obj performSelector:@selector(url)];
            if ([v isKindOfClass:[NSString class]]) return (NSString *)v;
            if ([v isKindOfClass:[NSURL class]]) return [(NSURL *)v absoluteString];
        }
        if ([obj respondsToSelector:@selector(urlString)]) {
            v = [obj performSelector:@selector(urlString)];
            if ([v isKindOfClass:[NSString class]]) return (NSString *)v;
        }
        // KVC 兜底
        v = [obj valueForKey:@"URL"]; if (!v) v = [obj valueForKey:@"url"]; if (!v) v = [obj valueForKey:@"urlString"];
        if ([v isKindOfClass:[NSString class]]) return (NSString *)v;
        if ([v isKindOfClass:[NSURL class]])    return [(NSURL *)v absoluteString];
    } @catch (...) {}
    return nil;
}

static void _reportSource(id source, NSString *from) {
    NSString *u = _extractURLStringFromObj(source);
    if (u.length) _reportURLString(u, from);
}

static void _swizzle(Class cls, SEL sel, IMP newIMP, IMP *origStore) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (origStore) *origStore = (IMP)method_getImplementation(m);
    method_setImplementation(m, newIMP);
}

#pragma mark - 1) AliPlayer 直传 URL 的入口

// - (int)setUrlSource:(AVPUrlSource *)
static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    _reportSource(source, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

// - (int)setLiveTimeShiftUrlSource:(AVPLiveTimeShiftUrlSource *)
static int (*orig_Ali_setLTS)(id, SEL, id);
static int swz_Ali_setLTS(id self, SEL _cmd, id source) {
    _reportSource(source, @"AliPlayer.setLiveTimeShiftUrlSource");
    return orig_Ali_setLTS(self, _cmd, source);
}

// - (int)prepareWithURL:(NSString *)  [部分包装层还在用]
static int (*orig_Ali_prepareURL)(id, SEL, NSString *);
static int swz_Ali_prepareURL(id self, SEL _cmd, NSString *url) {
    _reportURLString(url, @"AliyunVodPlayer.prepareWithURL");
    return orig_Ali_prepareURL(self, _cmd, url);
}
// - (int)play:(NSString *)
static int (*orig_Ali_playURL)(id, SEL, NSString *);
static int swz_Ali_playURL(id self, SEL _cmd, NSString *url) {
    _reportURLString(url, @"AliyunVodPlayer.play");
    return orig_Ali_playURL(self, _cmd, url);
}

#pragma mark - 2) AVPUrlSource 的 setter/getter（有的项目直接改这个）

// - (void)setURL:(NSURL *)
static void (*orig_AVP_setURL_NSURL)(id, SEL, NSURL *);
static void swz_AVP_setURL_NSURL(id self, SEL _cmd, NSURL *URL) {
    _reportURLString(URL.absoluteString, @"AVPUrlSource.setURL(NSUInteger)");
    orig_AVP_setURL_NSURL(self, _cmd, URL);
}

// - (void)setUrl:(NSString *)
static void (*orig_AVP_setUrl_NSString)(id, SEL, NSString *);
static void swz_AVP_setUrl_NSString(id self, SEL _cmd, NSString *url) {
    _reportURLString(url, @"AVPUrlSource.setUrl(NSString)");
    orig_AVP_setUrl_NSString(self, _cmd, url);
}

// - (NSURL *)URL
static id (*orig_AVP_getURL)(id, SEL);
static id swz_AVP_getURL(id self, SEL _cmd) {
    id u = orig_AVP_getURL(self, _cmd);
    _reportURLString([u isKindOfClass:[NSURL class]] ? [u absoluteString] : nil, @"AVPUrlSource.URL(getter)");
    return u;
}

// - (NSString *)url
static id (*orig_AVP_getUrlStr)(id, SEL);
static id swz_AVP_getUrlStr(id self, SEL _cmd) {
    id s = orig_AVP_getUrlStr(self, _cmd);
    if ([s isKindOfClass:[NSString class]]) _reportURLString(s, @"AVPUrlSource.url(getter)");
    return s;
}

#pragma mark - 3) Vid/Auth 方案（拿不到直链，但会触发网络兜底）

// - (int)setStsSource:(AVPVidStsSource *)
static int (*orig_Ali_setSts)(id, SEL, id);
static int swz_Ali_setSts(id self, SEL _cmd, id sts) {
    NSLog(@"[AliSniffer] setStsSource called (vid/auth模式) —— 将依赖网络兜底抓取 m3u8");
    return orig_Ali_setSts(self, _cmd, sts);
}

// - (int)setAuthSource:(AVPVidAuthSource *)
static int (*orig_Ali_setAuth)(id, SEL, id);
static int swz_Ali_setAuth(id self, SEL _cmd, id auth) {
    NSLog(@"[AliSniffer] setAuthSource called (vid/auth模式) —— 将依赖网络兜底抓取 m3u8");
    return orig_Ali_setAuth(self, _cmd, auth);
}

#pragma mark - 4) NSURLSession 兜底：抓所有含 m3u8/mpd/flv/playlist 的请求

static id (*orig_NSURLSession_dataTaskReq)(id, SEL, NSURLRequest *);
static id swz_NSURLSession_dataTaskReq(NSURLSession *self, SEL _cmd, NSURLRequest *req) {
    NSString *u = req.URL.absoluteString.lowercaseString;
    if ([u containsString:@"m3u8"] || [u containsString:@".mpd"] || [u containsString:@".flv"] || [u containsString:@"playlist"]) {
        _reportURLString(req.URL.absoluteString, @"NSURLSession.dataTaskWithRequest");
    }
    return orig_NSURLSession_dataTaskReq(self, _cmd, req);
}

static id (*orig_NSURLSession_dataTaskURL)(id, SEL, NSURL *);
static id swz_NSURLSession_dataTaskURL(NSURLSession *self, SEL _cmd, NSURL *url) {
    NSString *u = url.absoluteString.lowercaseString;
    if ([u containsString:@"m3u8"] || [u containsString:@".mpd"] || [u containsString:@".flv"] || [u containsString:@"playlist"]) {
        _reportURLString(url.absoluteString, @"NSURLSession.dataTaskWithURL");
    }
    return orig_NSURLSession_dataTaskURL(self, _cmd, url);
}

static id (*orig_NSURLSession_dataTaskReqCH)(id, SEL, NSURLRequest *, id);
static id swz_NSURLSession_dataTaskReqCH(NSURLSession *self, SEL _cmd, NSURLRequest *req, id handler) {
    NSString *u = req.URL.absoluteString.lowercaseString;
    if ([u containsString:@"m3u8"] || [u containsString:@".mpd"] || [u containsString:@".flv"] || [u containsString:@"playlist"]) {
        _reportURLString(req.URL.absoluteString, @"NSURLSession.dataTaskWithRequest:completionHandler:");
    }
    return orig_NSURLSession_dataTaskReqCH(self, _cmd, req, handler);
}

static id (*orig_NSURLSession_dataTaskURLCH)(id, SEL, NSURL *, id);
static id swz_NSURLSession_dataTaskURLCH(NSURLSession *self, SEL _cmd, NSURL *url, id handler) {
    NSString *u = url.absoluteString.lowercaseString;
    if ([u containsString:@"m3u8"] || [u containsString:@".mpd"] || [u containsString:@".flv"] || [u containsString:@"playlist"]) {
        _reportURLString(url.absoluteString, @"NSURLSession.dataTaskWithURL:completionHandler:");
    }
    return orig_NSURLSession_dataTaskURLCH(self, _cmd, url, handler);
}

#pragma mark - Install

__attribute__((constructor))
static void _ali_sniffer_init(void) {
    @autoreleasepool {
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        if (AliPlayer) {
            if ([AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
                _swizzle(AliPlayer, @selector(setUrlSource:), (IMP)swz_Ali_setUrlSource, (IMP *)&orig_Ali_setUrlSource);
                NSLog(@"[AliSniffer] hook AliPlayer.setUrlSource");
            }
            if ([AliPlayer instancesRespondToSelector:@selector(setLiveTimeShiftUrlSource:)]) {
                _swizzle(AliPlayer, @selector(setLiveTimeShiftUrlSource:), (IMP)swz_Ali_setLTS, (IMP *)&orig_Ali_setLTS);
                NSLog(@"[AliSniffer] hook AliPlayer.setLiveTimeShiftUrlSource");
            }
            if ([AliPlayer instancesRespondToSelector:@selector(setStsSource:)]) {
                _swizzle(AliPlayer, @selector(setStsSource:), (IMP)swz_Ali_setSts, (IMP *)&orig_Ali_setSts);
                NSLog(@"[AliSniffer] hook AliPlayer.setStsSource");
            }
            if ([AliPlayer instancesRespondToSelector:@selector(setAuthSource:)]) {
                _swizzle(AliPlayer, @selector(setAuthSource:), (IMP)swz_Ali_setAuth, (IMP *)&orig_Ali_setAuth);
                NSLog(@"[AliSniffer] hook AliPlayer.setAuthSource");
            }
        }

        Class AVPUrlSource = NSClassFromString(@"AVPUrlSource");
        if (AVPUrlSource) {
            if ([AVPUrlSource instancesRespondToSelector:@selector(setURL:)]) {
                _swizzle(AVPUrlSource, @selector(setURL:), (IMP)swz_AVP_setURL_NSURL, (IMP *)&orig_AVP_setURL_NSURL);
                NSLog(@"[AliSniffer] hook AVPUrlSource.setURL:NSURL");
            }
            if ([AVPUrlSource instancesRespondToSelector:@selector(setUrl:)]) {
                _swizzle(AVPUrlSource, @selector(setUrl:), (IMP)swz_AVP_setUrl_NSString, (IMP *)&orig_AVP_setUrl_NSString);
                NSLog(@"[AliSniffer] hook AVPUrlSource.setUrl:NSString");
            }
            if ([AVPUrlSource instancesRespondToSelector:@selector(URL)]) {
                _swizzle(AVPUrlSource, @selector(URL), (IMP)swz_AVP_getURL, (IMP *)&orig_AVP_getURL);
                NSLog(@"[AliSniffer] hook AVPUrlSource.URL(getter)");
            }
            if ([AVPUrlSource instancesRespondToSelector:@selector(url)]) {
                _swizzle(AVPUrlSource, @selector(url), (IMP)swz_AVP_getUrlStr, (IMP *)&orig_AVP_getUrlStr);
                NSLog(@"[AliSniffer] hook AVPUrlSource.url(getter)");
            }
        }

        Class AliVod = NSClassFromString(@"AliyunVodPlayer");
        if (AliVod) {
            if ([AliVod instancesRespondToSelector:@selector(prepareWithURL:)]) {
                _swizzle(AliVod, @selector(prepareWithURL:), (IMP)swz_Ali_prepareURL, (IMP *)&orig_Ali_prepareURL);
                NSLog(@"[AliSniffer] hook AliyunVodPlayer.prepareWithURL");
            }
            if ([AliVod instancesRespondToSelector:@selector(play:)]) {
                _swizzle(AliVod, @selector(play:), (IMP)swz_Ali_playURL, (IMP *)&orig_Ali_playURL);
                NSLog(@"[AliSniffer] hook AliyunVodPlayer.play");
            }
        }

        // NSURLSession 兜底（四个常用入口）
        Class S = [NSURLSession class];
        if ([S instancesRespondToSelector:@selector(dataTaskWithRequest:)]) {
            _swizzle(S, @selector(dataTaskWithRequest:), (IMP)swz_NSURLSession_dataTaskReq, (IMP *)&orig_NSURLSession_dataTaskReq);
            NSLog(@"[AliSniffer] hook NSURLSession.dataTaskWithRequest:");
        }
        if ([S instancesRespondToSelector:@selector(dataTaskWithURL:)]) {
            _swizzle(S, @selector(dataTaskWithURL:), (IMP)swz_NSURLSession_dataTaskURL, (IMP *)&orig_NSURLSession_dataTaskURL);
            NSLog(@"[AliSniffer] hook NSURLSession.dataTaskWithURL:");
        }
        if ([S instancesRespondToSelector:@selector(dataTaskWithRequest:completionHandler:)]) {
            _swizzle(S, @selector(dataTaskWithRequest:completionHandler:), (IMP)swz_NSURLSession_dataTaskReqCH, (IMP *)&orig_NSURLSession_dataTaskReqCH);
            NSLog(@"[AliSniffer] hook NSURLSession.dataTaskWithRequest:completionHandler:");
        }
        if ([S instancesRespondToSelector:@selector(dataTaskWithURL:completionHandler:)]) {
            _swizzle(S, @selector(dataTaskWithURL:completionHandler:), (IMP)swz_NSURLSession_dataTaskURLCH, (IMP *)&orig_NSURLSession_dataTaskURLCH);
            NSLog(@"[AliSniffer] hook NSURLSession.dataTaskWithURL:completionHandler:");
        }

        NSLog(@"[AliSniffer] ready.");
    }
}
