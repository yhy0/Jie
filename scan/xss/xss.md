>   基础漏洞实现之 XSS

## 检测 XSS

目前检测 xss 漏洞的几种方法：

-   简单粗暴的使用收集来的payload进行fuzz，通过页面是否回显来判断是否存在漏洞，就比如我刚开始用的[dalfox](https://github.com/hahwul/dalfox),发包量极大，弃用。
-   根据 html、js语法分析，确定回显位置和情况，然后对不同情况发送 payload，然后使用 html、js 语法分析判断是否多出标签、属性、js 语句等。
-   污点传播分析
-   原型链污染分析

### 语法分析

解析 html、js ,获取所有变量参数，确定回显参数。

如果参数可以回显，那么通过html解析就可以获得参数位置，分析回显的环境(比如是否在html标签内，是否在html属性内，是否在注释中，是否在js中)等等，以此来确定检测的payload。

具体请看 w8ay 师傅的文章[XSS 扫描器成长记](https://paper.seebug.org/1119/)

w13scan 中的实现：[xss.py](https://github.com/w-digital-scanner/w13scan/blob/HEAD/W13SCAN/scanners/PerFile/xss.py)
扫描流程

```
发送随机flag -> 确定参数回显 -> 确定回显位置以及情况(html，js语法解析) -> 根据情况根据不同payload探测 -> 使用html，js语法解析确定是否多出来了标签，属性，js语句等等
```

只能说 w8ay 师傅牛逼

### Dom

TODO 还是有待优化，检测的太少了

[xssfinder](https://github.com/ac0d3r/xssfinder) 中的 dom xss 检测方式，通过无头浏览器访问，劫持返回包，进行了污点分析，参考了[dom-based-xss-finder](https://github.com/AsaiKen/dom-based-xss-finder) chrome 插件的做法：

-   通过对 API 进行 hook，实现了 source、sink、taint 三类传播功能的 wrapper；
-   利用 AST 对网页中 JS 源码转成语义等价的、用 wrapper 实现的 JS 源码
-   wrapper 方法保证 JS 功能正确的同时，记录了 taint 的传播过程，最后上报。

>   Javascript 代码的**解析**(Parse)步骤分为两个阶段：词法分析(Lexical Analysis)和语法分析(Syntactic Analysis)。这个步骤接收代码并输出抽象语法树，亦称 AST。
>
>   具体的详细内容可以看这篇文章 https://pines-cheng.github.io/blog/#/posts/55

https://zhuanlan.zhihu.com/p/450310103

将上述缝合进 [katana](https://github.com/projectdiscovery/katana)爬虫，因 [katana](https://github.com/projectdiscovery/katana) 使用 [rod](https://github.com/go-rod/rod) 作为 Devtools 驱动, 需要研究一下类似的实现，流程

```
拦截返回包 --> 提取 js 并对 js 进行解析转换 --> 追加解析转换后的 js 代码到返回包中 --> 通过浏览器执行 js实现污染传播分析 --> 判断 rod 绑定运行时是否执行 --> dom xss
```

执行`preload.js`, `katana/pkg/engine/hybrid/crawl.go`的`navigateRequest`方法添加 

```go
//go:embed preload.js
var preloadJS string
...
page, err := browser.Page(proto.TargetCreateTarget{})

// 添加如下代码执行
// 绑定 js 中的 window.xssfinderPushDomVul
proto.RuntimeAddBinding{Name: eventPushVul}.Call(page)  
_, err = page.EvalOnNewDocument(preloadJS)
if err != nil {
    return nil, errorutil.NewWithTag("preloadJS", "could not create target(preloadJS)").Wrap(err)
}
// 然后添加一个劫持请求
router := page.HijackRequests()
defer router.MustStop()
// 劫持 html 和 js ，用于将<script>xxx</script>进行替换
router.MustAdd("*", func(ctx *rod.Hijack) {
   _ = ctx.LoadResponse(http.DefaultClient, true)
		if ctx.Request.Type() == proto.NetworkResourceTypeDocument {
			body := []byte(ctx.Response.Body())
			ss := scriptContentRex.FindAllSubmatch(body, -1)
			for i := range ss {
				convedBody, err := dom.HookParse(util.BytesToString(ss[i][1]))
				if err != nil {
					logging.Logger.Errorf("[dom-based] hookconv %v error: %s\n", ctx.Request.URL(), err)
					continue
				}
				body = bytes.Replace(body, ss[i][1], append(ss[i][1], util.StringToBytes("\n"+convedBody)...), 1)
			}

			ctx.Response.SetBody(body)
		} else if ctx.Request.Type() == proto.NetworkResourceTypeScript {
			body := ctx.Response.Body()
			convedBody, err := dom.HookParse(body)
			if err != nil {
				logging.Logger.Errorf("[dom-based] hookconv %v error: %s\n", ctx.Request.URL(), err)
			}
			ctx.Response.SetBody(body + "\n" + convedBody)
		}
})

go router.Run()
```

本来我是想在pageRouter.Start() 中直接替换的，但是替换中，发现这里并不影响返回包内容，也就无法执行替换后的 js 内容，后来又想渲染两次，想想还是直接拦截请求，将需要替换的内容拼接一下

最后修改 `crawler/katana/pkg/engine/hybrid/hijack.go` 的`Start`方法中实现事件监听

```go
wait := p.EachEvent(func(e *proto.FetchRequestPaused) {
    if handler != nil {
        err = handler(e)
    }
}, func(e *proto.RuntimeBindingCalled) {  // 实现绑定调用监听，接收污点分析结果
    switch e.Name {
    case eventPushVul:
        logging.Logger.Debug("[dom-based] EventBindingCalled", e.Payload)

        points := make([]dom.VulPoint, 0)
        if err := json.Unmarshal([]byte(e.Payload), &points); err != nil {
            logging.Logger.Errorln("[dom-based] json.Unmarshal error:", err)
            return
        }
        logging.Logger.Infoln(points)
    }
})
```



### 原型链污染

https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html

https://github.com/kleiton0x00/ppmap

利用已知和现有的小工具(检查全局环境中的特定变量)，但不涵盖代码分析或任何高级原型污染利用，通过原型污染执行XSS。

