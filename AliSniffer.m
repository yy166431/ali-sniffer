// AliSniffer.m  — 关键片段（示例）
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

static NSString * const kMessageHandlerName = @"aliSniffer";
static NSString * const kPushToken = @"@YourTokenHere"; // 上报 token
static NSString * const kPushEndpoint = @"http://your.server/api/push_raw"; // 上报接口

#pragma mark - JS to inject
static NSString * const kSnifferJS = @"(function(){"
"  function post(url){"
"    try{ window.webkit.messageHandlers.aliSniffer.postMessage({type:'found', url:url}); }catch(e){}"
"  }"
"  // helper: extract urls from text"
"  function extractUrls(text){"
"    var re = /https?:\\/\\/[^\\s\"'<>]+(?:m3u8|flv|\\.ts|auth_key=[0-9A-Za-z\\-_%]+)/ig;"
"    var out = [], m;"
"    while((m=re.exec(text))!==null) out.push(m[0]);"
"    return out;"
"  }"
"  // intercept XHR"
"  (function(){"
"    var _open = XMLHttpRequest.prototype.open;"
"    var _send = XMLHttpRequest.prototype.send;"
"    XMLHttpRequest.prototype.open = function(method, url){"
"      try{ this._ali_url = url; }catch(e){}"
"      return _open.apply(this, arguments);"
"    };"
"    XMLHttpRequest.prototype.send = function(body){"
"      var xhr = this;"
"      var _onload = function(){"
"        try{"
"          var text = xhr.responseText || '';"
"          var urls = extractUrls(text);"
"          for(var i=0;i<urls.length;i++) post(urls[i]);"
"        }catch(e){}"
"        if(xhr._ali_url) {"
"          var u = xhr._ali_url.toString();"
"          if(/auth_key=/.test(u)) post(u);"
"        }"
"      };"
"      try{ this.addEventListener('load', _onload, false);}catch(e){}"
"      return _send.apply(this, arguments);"
"    };"
"  })();"
"  // intercept fetch"
"  (function(){"
"    if(window.fetch){"
"      var _fetch = window.fetch;"
"      window.fetch = function(){"
"        return _fetch.apply(this, arguments).then(function(resp){"
"          try{"
"            var ct = resp.headers.get('content-type') || '';"
"            if(ct.indexOf('text')>=0 || ct.indexOf('json')>=0){"
"              resp.clone().text().then(function(t){"
"                var urls = extractUrls(t);"
"                urls.forEach(function(u){ post(u); });"
"              }).catch(function(){});"
"            }"
"          }catch(e){}"
"          return resp;"
"        });"
"      };"
"    }"
"  })();"
"  // monitor <video> src and attributes"
"  (function(){"
"    var obs = new MutationObserver(function(muts){"
"      muts.forEach(function(m){"
"        m.addedNodes && m.addedNodes.forEach(function(node){"
"          try{"
"            if(node.tagName && node.tagName.toLowerCase()==='video'){"
"              var s = node.getAttribute('src'); if(s) post(s);"
"            }"
"            if(node.querySelectorAll){"
"              var vids = node.querySelectorAll('video, source');"
"              vids.forEach(function(v){ var s=v.src||v.getAttribute('src'); if(s) post(s); });"
"            }"
"          }catch(e){}"
"        });"
"      });"
"    });"
"    obs.observe(document, {childList:true, subtree:true});"
"    // initial scan"
"    document.querySelectorAll('video, source, iframe').forEach(function(n){ var s = n.src||n.getAttribute('src'); if(s) post(s); });"
"  })();"
"  // hook common players (hls.js/flv.js/dash/aliyun)"
"  (function(){"
"    try{"
"      if(window.Hls && Hls.prototype){"
"        var _load = Hls.prototype.loadSource;"
"        Hls.prototype.loadSource = function(url){ post(url); return _load.apply(this, arguments); };"
"      }"
"    }catch(e){}"
"    try{"
"      if(window.flvjs && flvjs.createPlayer){"
"        var _create = flvjs.createPlayer;"
"        flvjs.createPlayer = function(cfg){ if(cfg && cfg.url) post(cfg.url); return _create.apply(this, arguments); };"
"      }"
"    }catch(e){}"
"    try{"
"      if(window.dashjs && dashjs && dashjs.MediaPlayer){"
"        var _attach = dashjs.MediaPlayer.prototype.attachSource;"
"        dashjs.MediaPlayer.prototype.attachSource = function(url){ post(url); return _attach.apply(this, arguments); };"
"      }"
"    }catch(e){}"
"    try{"
"      if(window.Aliplayer){"
"        var _ali = Aliplayer;"
"        Aliplayer = function(opt){ if(opt && opt.source) post(opt.source); return new _ali(opt); };"
"      }"
"    }catch(e){}"
"  })();"
"})();";

#pragma mark - Helper UI & upload
static void showPopupWithURL(NSString *url){
  dispatch_async(dispatch_get_main_queue(), ^{
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"抓到 URL (auth_key 优先)"
                                                                message:url
                                                         preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
      [[UIPasteboard generalPasteboard] setString:url];
    }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while(vc.presentedViewController) vc = vc.presentedViewController;
    [vc presentViewController:ac animated:YES completion:nil];
  });
}

static void uploadURLWithToken(NSString *url){
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kPushEndpoint]];
    req.HTTPMethod = @"POST";
    [req setValue:[NSString stringWithFormat:@"Bearer %@", kPushToken] forHTTPHeaderField:@"Authorization"];
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    NSDictionary *body = @{@"url": url, @"source": @"AliSniffer"};
    NSData *d = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    req.HTTPBody = d;
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable resp, NSError * _Nullable err) {
      // 可选地处理结果
    }] resume];
  });
}

#pragma mark - WKWebView swizzle & handler
@interface AliSnifferScriptHandler : NSObject <WKScriptMessageHandler>
@end
@implementation AliSnifferScriptHandler
- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message{
  if(![message.name isEqualToString:kMessageHandlerName]) return;
  NSDictionary *d = message.body;
  if(![d isKindOfClass:[NSDictionary class]]) return;
  NSString *type = d[@"type"];
  NSString *url = d[@"url"];
  if(type && [type isEqualToString:@"found"] && url.length>0){
    // 优先策略：先判断含 auth_key 的 URL
    if([url containsString:@"auth_key="]){
      showPopupWithURL(url);
      uploadURLWithToken(url);
    } else {
      // 也直接上报/弹窗（根据需要可延迟或合并去重）
      showPopupWithURL(url);
      uploadURLWithToken(url);
    }
  }
}
@end

// swizzle helper
static void swizzleWKWebViewInit(){
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    Class cls = objc_getClass("WKWebView");
    SEL origSel = @selector(initWithFrame:configuration:);
    Method origM = class_getInstanceMethod(cls, origSel);
    IMP origIMP = method_getImplementation(origM);
    // create new impl
    id newImpl = ^id(id self, CGRect frame, WKWebViewConfiguration *config){
      // call original
      id (*origFunc)(id, SEL, CGRect, WKWebViewConfiguration *) = (void *)origIMP;
      id webv = origFunc(self, origSel, frame, config);
      // avoid early hooking: delay a bit to reduce crash risk
      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        @try {
          if(!config) return;
          WKUserContentController *uc = config.userContentController;
          if(!uc){
            uc = [[WKUserContentController alloc] init];
            config.userContentController = uc;
          }
          // add script and message handler (avoid duplicates)
          // remove existing handler if any (safe-guard)
          @try { [uc removeScriptMessageHandlerForName:kMessageHandlerName]; } @catch(id e) {}
          AliSnifferScriptHandler *handler = [AliSnifferScriptHandler new];
          [uc addScriptMessageHandler:handler name:kMessageHandlerName];
          WKUserScript *us = [[WKUserScript alloc] initWithSource:(NSString*)kSnifferJS injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
          [uc addUserScript:us];
        } @catch (NSException *ex) {
          // ignore
        }
      });
      return webv;
    };
    IMP newIMP = imp_implementationWithBlock(newImpl);
    method_setImplementation(origM, newIMP);
  });
}

__attribute__((constructor))
static void init_sniffer(){
  // 延迟启动 swizzle，避免 app 启动早期问题
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
    swizzleWKWebViewInit();
  });
}
