// AliSniffer.m —— 专抓阿里云播放器的播放 URL (m3u8)

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

static void _copyToPasteboard(NSString *s) {
    if (!s.length) return;
    @try {
        [UIPasteboard generalPasteboard].string = s;
    } @catch (...) {}
    NSLog(@"[AliSniffer] copied: %@", s);
}

static void _reportURL(id urlObj, NSString *from) {
    NSString *u = nil;
    if ([urlObj isKindOfClass:[NSString class]]) {
        u = (NSString *)urlObj;
    } else if ([urlObj respondsToSelector:@selector(URL)]) {
        u = [[urlObj performSelector:@selector(URL)] absoluteString];
    }
    if (u.length) {
        NSLog(@"[AliSniffer] URL (%@): %@", from, u);
        if ([u containsString:@"m3u8"]) {
            _copyToPasteboard(u);
        }
    }
}

static void swizzle(Class cls, SEL sel, IMP newIMP, IMP *origStore) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (origStore) *origStore = (IMP)method_getImplementation(m);
    method_setImplementation(m, newIMP);
}

#pragma mark - 1) 阿里云 AliPlayer 系（存在则钩）

// AliPlayer: - (int)setUrlSource:(AVPUrlSource *)
static int (*orig_Ali_setUrlSource)(id, SEL, id);
static int swz_Ali_setUrlSource(id self, SEL _cmd, id source) {
    _reportURL(source, @"AliPlayer.setUrlSource");
    return orig_Ali_setUrlSource(self, _cmd, source);
}

// AliyunVodPlayer: - (int)prepareWithURL:(NSString *)
static int (*orig_Ali_prepareURL)(id, SEL, NSString *);
static int swz_Ali_prepareURL(id self, SEL _cmd, NSString *url) {
    _reportURL(url, @"AliyunVodPlayer.prepareWithURL");
    return orig_Ali_prepareURL(self, _cmd, url);
}

// AliyunVodPlayer: - (int)play:(NSString *)
static int (*orig_Ali_playURL)(id, SEL, NSString *);
static int swz_Ali_playURL(id self, SEL _cmd, NSString *url) {
    _reportURL(url, @"AliyunVodPlayer.play");
    return orig_Ali_playURL(self, _cmd, url);
}

__attribute__((constructor))
static void _ali_sniffer_init(void) {
    @autoreleasepool {
        Class AliPlayer = NSClassFromString(@"AliPlayer");
        Class AliVod   = NSClassFromString(@"AliyunVodPlayer");

        if (AliPlayer && [AliPlayer instancesRespondToSelector:@selector(setUrlSource:)]) {
            swizzle(AliPlayer, @selector(setUrlSource:), (IMP)swz_Ali_setUrlSource, (IMP *)&orig_Ali_setUrlSource);
            NSLog(@"[AliSniffer] hook AliPlayer.setUrlSource");
        }
        if (AliVod && [AliVod instancesRespondToSelector:@selector(prepareWithURL:)]) {
            swizzle(AliVod, @selector(prepareWithURL:), (IMP)swz_Ali_prepareURL, (IMP *)&orig_Ali_prepareURL);
            NSLog(@"[AliSniffer] hook AliyunVodPlayer.prepareWithURL");
        }
        if (AliVod && [AliVod instancesRespondToSelector:@selector(play:)]) {
            swizzle(AliVod, @selector(play:), (IMP)swz_Ali_playURL, (IMP *)&orig_Ali_playURL);
            NSLog(@"[AliSniffer] hook AliyunVodPlayer.play");
        }

        NSLog(@"[AliSniffer] ready.");
    }
}