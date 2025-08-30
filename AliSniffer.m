// AliSniffer.m —— 专抓阿里云播放器的播放 URL (m3u8)，仅嗅探不改播放行为

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

#pragma mark - 工具

static void _copyToPasteboard(NSString *s) {
    if (!s.length) return;
    @try { [UIPasteboard generalPasteboard].string = s; } @catch (...) {}
    NSLog(@"[AliSniffer] copied: %@", s);
}
static void _reportURLObj(id urlObj, NSString *from) {
    NSString *u = nil;
    if ([urlObj isKindOfClass:[NSString class]]) {
        u = (NSString *)urlObj;
    } else if ([urlObj respondsToSelector:@selector(URL)]) {
        // 兼容 AVPUrlSource.URL (NSURL *)
        id v = [urlObj performSelector:@selector(URL)];
        if ([v isKindOfClass:[NSURL class]]) u = [(NSURL *)v absoluteString];
    } else if ([urlObj isKindOfClass:[NSURL class]]) {
        u = [(NSURL *)urlObj absoluteString];
    }
    if (u.length) {
        NSLog(@"[AliSniffer] URL (%@): %@", from, u);
        NSString *low = u.lowercaseString;
        if ([low containsString:@"m3u8"] || [low containsString:@".mpd"] || [low containsString:@".flv"] || [low containsString:@"playlist"]) {
            _copyToPasteboard(u);
        }
    }
}

static void _swizzle(Class cls, SEL sel, IMP newIMP, IMP *origStore) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (origStore) *origStore = (IMP)method_getImplementation(m);
    method_setImplementation(m, newIMP);
}

#pragma mark - 1) AliPlayer: setUrlSource:

// - (int)setUrlSource:(AVPUrlSource *)
static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    _reportURLObj(source, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

#pragma mark - 2) AVPUrlSource: URL / setURL: （部分项目直接改这个）

static void (*orig_AVP_setURL)(id, SEL, NSURL *);
static void swz_AVP_setURL(id self, SEL _cmd, NSURL *URL) {
    _reportURLObj(URL, @"AVPUrlSource.setURL");
    orig_AVP_setURL(self, _cmd, URL);
}

static NSURL* (*orig_AVP_getURL)(id, SEL);
static NSURL* swz_AVP_getURL(id self, SEL _cmd) {
    NSURL *u = orig_AVP_getURL(self, _cmd);
    _reportURLObj(u, @"AVPUrlSource.URL(getter)");
    return u;
}

#pragma mark - 3) AliyunVodPlayer（老接口，部分项目仍在用）

// - (int)prepareWithURL:(NSString *)
static int (*orig_Ali_prepareURL)(id, SEL, NSString *);
static int swz_Ali_prepareURL(id self, SEL _cmd, NSString *url) {
    _reportURLObj(url, @"AliyunVodPlayer.prepareWithURL");
    return orig_Ali_prepareURL(self, _cmd, url);
}
// - (int)play:(NSString *)
static int (*orig_Ali_playURL)(id, SEL, NSString *);
static int swz_Ali_playURL(id self, SEL _cmd, NSString *url) {
    _reportURLObj(url, @"AliyunVodPlayer.play");
    return orig_Ali_playURL(self, _cmd, url);
}

#pragma mark - 4) 兜底：NSURLSession.dataTaskWithRequest:（只打印含 m3u8/mpd/flv/playlist）

static id (*orig_NSURLSession_dataTaskReq)(id, SEL, NSURLRequest *);
static id swz_NSURLSession_dataTaskReq(NSURLSession *self, SEL _cmd, NSURLRequest *req) {
    NSURL *u = req.URL;
    NSString *s = u.absoluteString.lowercaseString;
    if ([s containsString:@"m3u8"] || [s containsString:@".mpd"] || [s containsString:@".flv"] || [s containsString:@"playlist"]) {
        _reportURLObj(u, @"NSURLSession.dataTaskWithRequest");
    }
    return orig_NSURLSession_dataTaskReq(self, _cmd, req);
}

#pragma mark - 安装钩子

__attribute__((constructor))
static void _ali_sniffer_init(void) {
    @autoreleasepool {
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        if (AliPlayer && [AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
            _swizzle(AliPlayer, @selector(setUrlSource:), (IMP)swz_Ali_setUrlSource, (IMP *)&orig_Ali_setUrlSource);
            NSLog(@"[AliSniffer] hook AliPlayer.setUrlSource");
        }

        Class AVPUrlSource = NSClassFromString(@"AVPUrlSource");
        if (AVPUrlSource) {
            if ([AVPUrlSource instancesRespondToSelector:@selector(setURL:)]) {
                _swizzle(AVPUrlSource, @selector(setURL:), (IMP)swz_AVP_setURL, (IMP *)&orig_AVP_setURL);
                NSLog(@"[AliSniffer] hook AVPUrlSource.setURL:");
            }
            if ([AVPUrlSource instancesRespondToSelector:@selector(URL)]) {
                _swizzle(AVPUrlSource, @selector(URL), (IMP)swz_AVP_getURL, (IMP *)&orig_AVP_getURL);
                NSLog(@"[AliSniffer] hook AVPUrlSource.URL(getter)");
            }
        }

        Class AliVod = NSClassFromString(@"AliyunVodPlayer");
        if (AliVod && [AliVod instancesRespondToSelector:@selector(prepareWithURL:)]) {
            _swizzle(AliVod, @selector(prepareWithURL:), (IMP)swz_Ali_prepareURL, (IMP *)&orig_Ali_prepareURL);
            NSLog(@"[AliSniffer] hook AliyunVodPlayer.prepareWithURL:");
        }
        if (AliVod && [AliVod instancesRespondToSelector:@selector(play:)]) {
            _swizzle(AliVod, @selector(play:), (IMP)swz_Ali_playURL, (IMP *)&orig_Ali_playURL);
            NSLog(@"[AliSniffer] hook AliyunVodPlayer.play:");
        }

        // NSURLSession 兜底（非强制）
        if ([NSURLSession instancesRespondToSelector:@selector(dataTaskWithRequest:)]) {
            _swizzle([NSURLSession class], @selector(dataTaskWithRequest:), (IMP)swz_NSURLSession_dataTaskReq, (IMP *)&orig_NSURLSession_dataTaskReq);
            NSLog(@"[AliSniffer] hook NSURLSession.dataTaskWithRequest");
        }

        NSLog(@"[AliSniffer] ready.");
    }
}
