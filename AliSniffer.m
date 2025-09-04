// iOS14 / TrollStore 注入可用
// 功能：抓取播放请求（URL+Headers+来源+时间）→ 悬浮球 → 列表查看/复制
// 覆盖点：NSURLSessionTask / NSURLSessionConfiguration(NSURLProtocol) / AVPlayerItem & AVURLAsset
//         CFReadStream(fishhook) / WKWebView(JS 注入) / （可选）libcurl
// 注意：不打印 NSLog，不写文件，不发网络，仅本地 UI。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

#pragma mark - 配置

// 过滤噪声（上报/埋点）
static NSArray<NSString *> *BlockedSubstrings(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{ a = @[
        @"log.aliyuncs.com", @"/beacon", @"/collect", @"/monitor", @"umeng", @"bugly", @"crash", @"sentry"
    ];});
    return a;
}

// 白名单域名：即使无后缀也提示
static NSArray<NSString *> *WhitelistedHosts(void) {
    static NSArray *a; static dispatch_once_t once;
    dispatch_once(&once, ^{ a = @[
        @"knyb.kuniunet.com",
        @"knydb.kuniunet.com",
        @"qiaohongb.kuniunet.com",
        @"v2.weizan.cn"
    ];});
    return a;
}

static inline NSString *HostOfURLString(NSString *s) {
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.lowercaseString ?: @"";
}
static inline BOOL IsNoise(NSString *lower) {
    for (NSString *k in BlockedSubstrings()) if ([lower containsString:k]) return YES;
    return NO;
}
static inline BOOL IsPlayable(NSString *u) {
    if (u.length == 0) return NO;
    NSString *s = u.lowercaseString;
    if ([s containsString:@"m3u8"] ||
        [s containsString:@".mp4"] ||
        [s containsString:@".flv"] ||
        [s hasPrefix:@"rtmp://"] || [s hasPrefix:@"rtmps://"] ||
        (([s hasPrefix:@"ws://"] || [s hasPrefix:@"wss://"]) && [s containsString:@".flv"])) return YES;
    NSString *h = HostOfURLString(s);
    for (NSString *w in WhitelistedHosts()) if ([h hasSuffix:w]) return YES;
    return NO;
}

#pragma mark - 数据模型与存储（内存，线程安全）

@interface SFCaptureItem : NSObject
@property(nonatomic,copy) NSString *url;
@property(nonatomic,copy) NSDictionary<NSString*,NSString*> *headers;
@property(nonatomic,copy) NSString *source;   // 命中的钩子来源标记
@property(nonatomic,strong) NSDate *time;
@end
@implementation SFCaptureItem @end

@interface SFCaptureStore : NSObject
@property(nonatomic,strong) NSMutableArray<SFCaptureItem*> *items;
@property(nonatomic,strong) NSMutableSet<NSString*> *dedup; // url+UA+Referer+Cookie 10s 去重
@property(nonatomic,strong) dispatch_queue_t q;
+ (instancetype)shared;
- (void)addURL:(NSString *)url headers:(NSDictionary *)headers source:(NSString *)source;
- (NSArray<SFCaptureItem*> *)allItems;
@end

@implementation SFCaptureStore
+ (instancetype)shared { static SFCaptureStore *s; static dispatch_once_t once; dispatch_once(&once, ^{ s=[SFCaptureStore new];
    s.items = [NSMutableArray array]; s.dedup=[NSMutableSet set]; s.q = dispatch_queue_create("sf.store", DISPATCH_QUEUE_SERIAL);
}); return s; }

- (NSString *)keyFor:(NSString *)url headers:(NSDictionary*)h {
    NSString *ua = h[@"User-Agent"] ?: @"";
    NSString *rf = h[@"Referer"] ?: @"";
    NSString *ck = h[@"Cookie"] ?: @"";
    return [NSString stringWithFormat:@"%@|%@|%@|%@", url ?: @"", ua, rf, ck];
}

- (void)addURL:(NSString *)url headers:(NSDictionary *)headers source:(NSString *)source {
    if (url.length == 0) return;
    NSString *lower = url.lowercaseString;
    if (IsNoise(lower) || !IsPlayable(lower)) return;
    // 补全常见头（仅用于展示/mpv 生成；不改原请求）
    NSMutableDictionary *hdr = [NSMutableDictionary dictionaryWithDictionary:headers ?: @{}];
    NSURL *U = [NSURL URLWithString:url];
    NSString *base = (U.scheme && U.host) ? [NSString stringWithFormat:@"%@://%@", U.scheme, U.host] : @"";
    if (!hdr[@"Referer"] && base.length) hdr[@"Referer"] = base;
    if (!hdr[@"Origin"] && base.length)  hdr[@"Origin"]  = base;
    if (!hdr[@"User-Agent"]) hdr[@"User-Agent"] = [NSString stringWithFormat:@"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X)", UIDevice.currentDevice.systemVersion];

    dispatch_async(self.q, ^{
        NSString *key = [self keyFor:url headers:hdr];
        // 10 秒去重
        static NSMutableDictionary<NSString*,NSDate*> *last; if (!last) last = [NSMutableDictionary dictionary];
        NSDate *now = [NSDate date];
        NSDate *prev = last[key];
        if (prev && [now timeIntervalSinceDate:prev] < 10.0) return;
        last[key] = now;

        SFCaptureItem *it = [SFCaptureItem new];
        it.url = url; it.headers = hdr; it.source = source ?: @"(unknown)"; it.time = now;
        // 仅保留最近 200 条
        if (self.items.count >= 200) [self.items removeObjectAtIndex:0];
        [self.items addObject:it];
        // 通知 UI 刷新
        dispatch_async(dispatch_get_main_queue(), ^{ [[NSNotificationCenter defaultCenter] postNotificationName:@"sf_store_changed" object:nil]; });
    });
}
- (NSArray<SFCaptureItem*> *)allItems {
    __block NSArray *arr = nil;
    dispatch_sync(self.q, ^{ arr = [self.items copy]; });
    return arr;
}
@end

#pragma mark - UI：悬浮球 & 列表

@interface SFFloatWindow : UIWindow @end
@implementation SFFloatWindow
- (BOOL)pointInside:(CGPoint)p withEvent:(UIEvent *)e { // 仅按钮区域响应
    UIView *btn = self.subviews.firstObject;
    return btn ? CGRectContainsPoint(btn.frame, p) : NO;
}
@end

@interface SFListVC : UITableViewController @end

@interface SFFloat : NSObject
@property(nonatomic,strong) SFFloatWindow *win;
@property(nonatomic,strong) UIButton *ball;
+ (instancetype)shared;
- (void)ensure;
@end

@implementation SFFloat
+ (instancetype)shared { static SFFloat *s; static dispatch_once_t once; dispatch_once(&once, ^{ s=[SFFloat new]; }); return s; }
- (void)ensure {
    if (self.win) return;
    self.win = [[SFFloatWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.win.windowLevel = UIWindowLevelStatusBar + 1;
    self.win.backgroundColor = UIColor.clearColor;

    CGFloat d = 54;
    self.ball = [UIButton buttonWithType:UIButtonTypeCustom];
    self.ball.frame = CGRectMake([UIScreen mainScreen].bounds.size.width - d - 12, [UIScreen mainScreen].bounds.size.height*0.6, d, d);
    self.ball.layer.cornerRadius = d/2.0;
    self.ball.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.55];
    [self.ball setTitle:@"流" forState:UIControlStateNormal];
    self.ball.titleLabel.font = [UIFont boldSystemFontOfSize:20];
    [self.ball addTarget:self action:@selector(openList) forControlEvents:UIControlEventTouchUpInside];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(pan:)];
    [self.ball addGestureRecognizer:pan];

    [self.win addSubview:self.ball];
    self.win.hidden = NO;
}
- (void)openList {
    SFListVC *vc = [SFListVC new];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;
    UIWindow *key = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
    UIViewController *top = key.rootViewController;
    while (top.presentedViewController) top = top.presentedViewController;
    [top presentViewController:nav animated:YES completion:nil];
}
- (void)pan:(UIPanGestureRecognizer *)g {
    UIView *v = g.view;
    if (g.state == UIGestureRecognizerStateChanged || g.state == UIGestureRecognizerStateEnded) {
        CGPoint t = [g translationInView:v.superview];
        v.center = CGPointMake(v.center.x + t.x, v.center.y + t.y);
        [g setTranslation:CGPointZero inView:v.superview];
    }
}
@end

@interface SFDetailVC : UIViewController
@property(nonatomic,strong) SFCaptureItem *item;
@end

@implementation SFListVC
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"抓到的播放请求";
    self.tableView.tableFooterView = [UIView new];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"清空" style:0 target:self action:@selector(clear)];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(reload) name:@"sf_store_changed" object:nil];
}
- (void)dealloc { [[NSNotificationCenter defaultCenter] removeObserver:self]; }
- (void)clear { [SFCaptureStore shared].items.removeAllObjects; [self.tableView reloadData]; }
- (void)reload { [self.tableView reloadData]; }
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)section { return [SFCaptureStore shared].allItems.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:@"c"]; if (!cell) cell=[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"c"];
    SFCaptureItem *it = [SFCaptureStore shared].allItems[ip.row];
    cell.textLabel.text = it.url;
    cell.textLabel.numberOfLines = 2;
    NSDateFormatter *fmt = [NSDateFormatter new]; fmt.dateFormat = @"HH:mm:ss";
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ · %@", [fmt stringFromDate:it.time], it.source ?: @""];
    cell.detailTextLabel.textColor = [UIColor grayColor];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return cell;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    SFDetailVC *d = [SFDetailVC new];
    d.item = [SFCaptureStore shared].allItems[ip.row];
    [self.navigationController pushViewController:d animated:YES];
}
@end

@implementation SFDetailVC
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"请求详情";
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    UITextView *tv = [[UITextView alloc] initWithFrame:self.view.bounds];
    tv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    tv.editable = NO; tv.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];

    NSMutableString *s = [NSMutableString stringWithFormat:@"Source: %@\nTime: %@\n\nURL:\n%@\n", self.item.source ?: @"", self.item.time, self.item.url];
    if (self.item.headers.count) {
        [s appendString:@"\nHeaders:\n"];
        NSArray *keys = [[self.item.headers allKeys] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
        for (NSString *k in keys) [s appendFormat:@"%@: %@\n", k, self.item.headers[k]];
    }
    // 生成 mpv 命令
    NSMutableArray *hdrPairs = [NSMutableArray array];
    for (NSString *k in self.item.headers) {
        NSString *v = self.item.headers[k];
        if (!v.length) continue;
        // mpv 支持多次 --http-header-fields
        [hdrPairs addObject:[NSString stringWithFormat:@"--http-header-fields=\"%@: %@\"", k, v]];
    }
    NSString *mpv = [NSString stringWithFormat:@"mpv \"%@\" \\\n  %@",
                     self.item.url, [hdrPairs componentsJoinedByString:@" \\\n  "]];
    [s appendFormat:@"\n\nmpv 命令（复制后可在 Windows 直接用）：\n%@\n", mpv];

    tv.text = s;
    [self.view addSubview:tv];

    UIBarButtonItem *copyURL = [[UIBarButtonItem alloc] initWithTitle:@"复制URL" style:0 target:self action:@selector(copyURL)];
    UIBarButtonItem *copyHdr = [[UIBarButtonItem alloc] initWithTitle:@"复制头" style:0 target:self action:@selector(copyHdr)];
    UIBarButtonItem *copyMPV = [[UIBarButtonItem alloc] initWithTitle:@"复制mpv" style:0 target:self action:@selector(copyMPV)];
    self.navigationItem.rightBarButtonItems = @[copyMPV, copyHdr, copyURL];
}
- (void)copyURL { UIPasteboard.generalPasteboard.string = self.item.url ?: @""; }
- (void)copyHdr {
    NSMutableString *h = [NSMutableString string];
    NSArray *keys = [[self.item.headers allKeys] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    for (NSString *k in keys) [h appendFormat:@"%@: %@\n", k, self.item.headers[k]];
    UIPasteboard.generalPasteboard.string = h;
}
- (void)copyMPV {
    NSMutableArray *hdrPairs = [NSMutableArray array];
    for (NSString *k in self.item.headers) {
        NSString *v = self.item.headers[k];
        if (!v.length) continue;
        [hdrPairs addObject:[NSString stringWithFormat:@"--http-header-fields=\"%@: %@\"", k, v]];
    }
    NSString *mpv = [NSString stringWithFormat:@"mpv \"%@\" %@", self.item.url, [hdrPairs componentsJoinedByString:@" "]];
    UIPasteboard.generalPasteboard.string = mpv;
}
@end

#pragma mark - 统一上报入口

static void SF_ReportRequest(NSURLRequest *req, NSString *source) {
    if (!req || !req.URL) return;
    NSString *url = req.URL.absoluteString ?: @"";
    if (!url.length) return;
    if (IsNoise(url.lowercaseString) || !IsPlayable(url)) return;

    NSMutableDictionary *hdr = [NSMutableDictionary dictionaryWithDictionary:req.allHTTPHeaderFields ?: @{}];
    [[SFCaptureStore shared] addURL:url headers:hdr source:source];
    [[SFFloat shared] ensure];
}
static void SF_ReportURLOnly(NSString *url, NSString *source) {
    if (url.length == 0) return;
    if (IsNoise(url.lowercaseString) || !IsPlayable(url)) return;
    [[SFCaptureStore shared] addURL:url headers:@{} source:source];
    [[SFFloat shared] ensure];
}

#pragma mark - Swizzle Helper

static void Swz(Class c, SEL sel, IMP newImp, IMP *origStore) {
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    if (origStore) *origStore = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

#pragma mark - Hook 1: NSURLSessionTask.resume

static void (*orig_task_resume)(id, SEL);
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if ([self respondsToSelector:@selector(currentRequest)]) {
            NSURLRequest *req = [self performSelector:@selector(currentRequest)];
            if ([req isKindOfClass:NSURLRequest.class]) SF_ReportRequest(req, @"NSURLSessionTask.resume");
        }
    } @catch (...) {}
    orig_task_resume(self, _cmd);
}

#pragma mark - Hook 2: NSURLProtocol (MIME / #EXTM3U)

@interface SFSniffProto : NSURLProtocol <NSURLSessionDataDelegate>
@property(nonatomic,strong) NSURLSessionDataTask *task;
@property(nonatomic,strong) NSMutableData *buf;
@property(nonatomic,assign) BOOL shouted;
@end

@implementation SFSniffProto
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"SFSniffHandled" inRequest:request]) return NO;
    NSString *sch = request.URL.scheme.lowercaseString;
    return [sch isEqualToString:@"http"] || [sch isEqualToString:@"https"];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"SFSniffHandled" inRequest:r];
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:r];
    self.buf = [NSMutableData data];
    [self.task resume];
}
- (void)stopLoading { [self.task cancel]; self.task = nil; self.buf=nil; }

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
 didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];

    if (!self.shouted) {
        NSString *mime = response.MIMEType.lowercaseString ?: @"";
        if ([mime containsString:@"mpegurl"]) {
            SF_ReportRequest(dataTask.currentRequest, @"NSURLProtocol(MIME-M3U8)");
            self.shouted = YES;
        } else if ([mime containsString:@"x-flv"] || [mime containsString:@"/flv"]) {
            SF_ReportRequest(dataTask.currentRequest, @"NSURLProtocol(MIME-FLV)");
            self.shouted = YES;
        }
    }
    completionHandler(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
    if (!self.shouted && self.buf.length < 16*1024) {
        [self.buf appendData:data];
        NSString *head = [[NSString alloc] initWithData:self.buf encoding:NSUTF8StringEncoding];
        if (head && [head containsString:@"#EXTM3U"]) {
            SF_ReportRequest(dataTask.currentRequest, @"NSURLProtocol(#EXTM3U)");
            self.shouted = YES;
        }
    }
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) [self.client URLProtocol:self didFailWithError:error];
    else [self.client URLProtocolDidFinishLoading:self];
}
@end

static NSURLSessionConfiguration* (*orig_defCfg)(id, SEL);
static NSURLSessionConfiguration* swz_defCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_defCfg(self, _cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:SFSniffProto.class]) [arr insertObject:SFSniffProto.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}
static NSURLSessionConfiguration* (*orig_ephCfg)(id, SEL);
static NSURLSessionConfiguration* swz_ephCfg(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_ephCfg(self, _cmd);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:SFSniffProto.class]) [arr insertObject:SFSniffProto.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}
static NSURLSessionConfiguration* (*orig_bgCfg)(id, SEL, NSString *);
static NSURLSessionConfiguration* swz_bgCfg(id self, SEL _cmd, NSString *identifier) {
    NSURLSessionConfiguration *cfg = orig_bgCfg(self, _cmd, identifier);
    NSMutableArray *arr = [cfg.protocolClasses mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:SFSniffProto.class]) [arr insertObject:SFSniffProto.class atIndex:0];
    cfg.protocolClasses = arr;
    return cfg;
}

#pragma mark - Hook 3: CFReadStream (fishhook)

typedef CFURLRef (*PFN_CFHTTPMessageCopyRequestURL)(CFHTTPMessageRef);
static PFN_CFHTTPMessageCopyRequestURL p_CFHTTPMessageCopyRequestURL = NULL;
typedef CFReadStreamRef (*PFN_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef, CFHTTPMessageRef);
static PFN_CFReadStreamCreateForHTTPRequest orig_CFReadStreamCreateForHTTPRequest = NULL;

static CFReadStreamRef hook_CFReadStreamCreateForHTTPRequest(CFAllocatorRef a, CFHTTPMessageRef req) {
    if (req && p_CFHTTPMessageCopyRequestURL) {
        CFURLRef u = p_CFHTTPMessageCopyRequestURL(req);
        if (u) { NSString *s = [(__bridge NSURL *)u absoluteString]; if (s.length) SF_ReportURLOnly(s, @"CFReadStreamCreateForHTTPRequest"); }
    }
    return orig_CFReadStreamCreateForHTTPRequest ? orig_CFReadStreamCreateForHTTPRequest(a, req) : NULL;
}

#pragma mark - Hook 4: AVPlayer / AVURLAsset

static id (*orig_AVPI_initWithURL)(id, SEL, NSURL *);
static id swz_AVPI_initWithURL(id self, SEL _cmd, NSURL *url) {
    if (url) SF_ReportURLOnly(url.absoluteString, @"AVPlayerItem.initWithURL");
    return orig_AVPI_initWithURL(self, _cmd, url);
}
static id (*orig_AVPI_playerItemWithURL)(id, SEL, NSURL *);
static id swz_AVPI_playerItemWithURL(id self, SEL _cmd, NSURL *url) {
    if (url) SF_ReportURLOnly(url.absoluteString, @"AVPlayerItem.playerItemWithURL");
    return orig_AVPI_playerItemWithURL(self, _cmd, url);
}
static id (*orig_AVURLA_initWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_initWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) {
    if (url) SF_ReportURLOnly(url.absoluteString, @"AVURLAsset.initWithURL");
    return orig_AVURLA_initWithURL(self, _cmd, url, opt);
}
static id (*orig_AVURLA_assetWithURL)(id, SEL, NSURL *, NSDictionary *);
static id swz_AVURLA_assetWithURL(id self, SEL _cmd, NSURL *url, NSDictionary *opt) {
    if (url) SF_ReportURLOnly(url.absoluteString, @"AVURLAsset.assetWithURL");
    return orig_AVURLA_assetWithURL(self, _cmd, url, opt);
}

#pragma mark - Hook 5: WKWebView (JS 注入)

@interface SFWKHandler : NSObject<WKScriptMessageHandler> @end
@implementation SFWKHandler
- (void)userContentController:(WKUserContentController *)uc didReceiveScriptMessage:(WKScriptMessage *)m {
    if ([m.name isEqualToString:@"_SF"]) {
        NSString *u = [m.body isKindOfClass:NSString.class] ? (NSString *)m.body : @"";
        if (u.length) SF_ReportURLOnly(u, @"WKWebView(JS)");
    }
}
@end

static id (*orig_WK_init)(id, SEL, CGRect, WKWebViewConfiguration *);
static id swz_WK_init(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    if (cfg) {
        SFWKHandler *h = [SFWKHandler new];
        [cfg.userContentController addScriptMessageHandler:h name:@"_SF"];
        NSString *js =
        @"(function(){function r(u){try{if(u&&/(m3u8|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)/i.test(u)){window.webkit.messageHandlers._SF.postMessage(u);}}catch(e){}}"
         "var f=window.fetch;if(f){window.fetch=function(){var u=arguments[0];if(typeof u==='string'){r(u);}return f.apply(this,arguments).then(function(res){try{var u=res&&res.url;if(u)r(u);}catch(e){}return res;});};}"
         "var X=window.XMLHttpRequest;if(X){var o=X.prototype.open,s=X.prototype.send;X.prototype.open=function(m,u){try{this.__u=u;r(u);}catch(e){}return o.apply(this,arguments)};X.prototype.send=function(){try{r(this.__u);}catch(e){}return s.apply(this,arguments)};}"
         "if(window.HTMLMediaElement){var d=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');if(d&&d.set){Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{r(v);}catch(e){}return d.set.call(this,v);},get:d.get});}}"
        "})();";
        WKUserScript *sc = [[WKUserScript alloc] initWithSource:js injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
        [cfg.userContentController addUserScript:sc];
        objc_setAssociatedObject(cfg, "_sf_wk_h", h, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(cfg, "_sf_wk_s", sc, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return orig_WK_init(self, _cmd, frame, cfg);
}

#pragma mark - Hook 6: libcurl（可选）

typedef int CURLcode;
static CURLcode (*orig_curl_easy_setopt)(void *curl, int option, ...);
static CURLcode hook_curl_easy_setopt(void *curl, int option, ...) {
    va_list ap; va_start(ap, option);
    if (option == 10002 /* CURLOPT_URL */) {
        const char *c = va_arg(ap, const char *); if (c) { NSString *u = [NSString stringWithUTF8String:c]; if (u.length) SF_ReportURLOnly(u, @"curl_easy_setopt(CURLOPT_URL)"); }
        va_end(ap); va_start(ap, option); (void)va_arg(ap, const char *);
    }
    CURLcode ret = 0;
    if (orig_curl_easy_setopt) { const void *p = va_arg(ap, const void *); ret = orig_curl_easy_setopt(curl, option, p); }
    va_end(ap); return ret;
}
static inline void HookCurlIfPresent(void) {
    rebind_symbols((struct rebinding[]){{"curl_easy_setopt",(void*)hook_curl_easy_setopt,(void**)&orig_curl_easy_setopt}},1);
}

#pragma mark - 安装所有 Hook（入口）

__attribute__((constructor))
static void _sf_init(void) {
    @autoreleasepool {
        // 悬浮球先准备（首次抓到时也会 ensure）
        [[SFFloat shared] ensure];

        // NSURLSessionTask.resume
        Class Task = NSClassFromString(@"NSURLSessionTask");
        if (Task && class_getInstanceMethod(Task, @selector(resume))) Swz(Task, @selector(resume), (IMP)swz_task_resume, (IMP *)&orig_task_resume);

        // NSURLSessionConfiguration（default / ephemeral / background）
        Class Cfg = NSURLSessionConfiguration.class;
        if (Cfg) {
            Method m1 = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
            if (m1) { orig_defCfg = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)swz_defCfg); }
            Method m2 = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
            if (m2) { orig_ephCfg = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)swz_ephCfg); }
            if ([Cfg respondsToSelector:@selector(backgroundSessionConfigurationWithIdentifier:)]) {
                Method m3 = class_getClassMethod(Cfg, @selector(backgroundSessionConfigurationWithIdentifier:));
                if (m3) { orig_bgCfg = (void *)method_getImplementation(m3); method_setImplementation(m3, (IMP)swz_bgCfg); }
            }
        }

        // CFReadStream（fishhook）
        void *hCF = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_NOW);
        if (hCF) p_CFHTTPMessageCopyRequestURL = (PFN_CFHTTPMessageCopyRequestURL)dlsym(hCF, "CFHTTPMessageCopyRequestURL");
        rebind_symbols((struct rebinding[]){{"CFReadStreamCreateForHTTPRequest",(void*)hook_CFReadStreamCreateForHTTPRequest,(void**)&orig_CFReadStreamCreateForHTTPRequest}},1);

        // AVPlayer / AVURLAsset
        Class PI = NSClassFromString(@"AVPlayerItem");
        if (PI) {
            Method m1 = class_getInstanceMethod(PI, @selector(initWithURL:));
            if (m1) { orig_AVPI_initWithURL = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)swz_AVPI_initWithURL); }
            Method m2 = class_getClassMethod(PI, @selector(playerItemWithURL:));
            if (m2) { orig_AVPI_playerItemWithURL = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)swz_AVPI_playerItemWithURL); }
        }
        Class UA = NSClassFromString(@"AVURLAsset");
        if (UA) {
            Method m3 = class_getInstanceMethod(UA, @selector(initWithURL:options:));
            if (m3) { orig_AVURLA_initWithURL = (void *)method_getImplementation(m3); method_setImplementation(m3, (IMP)swz_AVURLA_initWithURL); }
            Method m4 = class_getClassMethod(UA, @selector(URLAssetWithURL:options:));
            if (m4) { orig_AVURLA_assetWithURL = (void *)method_getImplementation(m4); method_setImplementation(m4, (IMP)swz_AVURLA_assetWithURL); }
        }

        // WKWebView
        Class WK = NSClassFromString(@"WKWebView");
        if (WK) {
            Method m = class_getInstanceMethod(WK, @selector(initWithFrame:configuration:));
            if (m) { orig_WK_init = (void *)method_getImplementation(m); method_setImplementation(m, (IMP)swz_WK_init); }
        }

        // libcurl（可选）
        HookCurlIfPresent();
    }
}
