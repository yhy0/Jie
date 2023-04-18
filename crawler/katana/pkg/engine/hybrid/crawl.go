package hybrid

import (
	"bytes"
	"github.com/go-rod/rod"
	JieConf "github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/protocols/headless"
	"github.com/yhy0/Jie/pkg/util"
	"github.com/yhy0/Jie/scan/sensitive"
	"github.com/yhy0/Jie/scan/xss/dom"
	"github.com/yhy0/logging"
	"io"
	"net/http"
	"net/http/httputil"
	"regexp"
	"runtime"

	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	mapsutil "github.com/projectdiscovery/utils/maps"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/yhy0/Jie/crawler/katana/pkg/engine/common"
	"github.com/yhy0/Jie/crawler/katana/pkg/engine/parser"
	"github.com/yhy0/Jie/crawler/katana/pkg/navigation"
	"github.com/yhy0/Jie/crawler/katana/pkg/utils"
)

var (
	eventPushVul = "xssfinderPushDomVul"
	// 提取 script 部分，用于 js ast
	scriptContentRex = regexp.MustCompile(`<script[^/>]*?>(?:\s*<!--)?\s*(\S[\s\S]+?\S)\s*(?:-->\s*)?<\/script>`)
)

func (c *Crawler) navigateRequest(s *common.CrawlSession, request *navigation.Request) (*navigation.Response, error) {
	// todo 怎么写，才能没有 panic ，现在已知 Must** 字样的都有可能导致
	defer func() {
		if err := recover(); err != nil {
			logging.Logger.Errorln(request.URL, "recover from:", err)
			debugStack := make([]byte, 1024)
			runtime.Stack(debugStack, false)
			logging.Logger.Errorf("Stack Trace:%v", string(debugStack))

		}
	}()
	depth := request.Depth + 1
	response := &navigation.Response{
		Depth:        depth,
		RootHostname: s.Hostname,
	}

	page, err := s.Browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, errorutil.NewWithTag("hybrid", "could not create target").Wrap(err)
	}
	defer page.Close()

	// todo yhy 绕过无头浏览器检测 https://bot.sannysoft.com
	_, err = page.EvalOnNewDocument(headless.StealthJS)
	if err != nil {
		logging.Logger.Errorln(err)
		return nil, err
	}

	// 绑定 js 中的 window.xssfinderPushDomVul
	proto.RuntimeAddBinding{Name: eventPushVul}.Call(page)
	_, err = page.EvalOnNewDocument(headless.PreloadJS)
	if err != nil {
		logging.Logger.Errorln(err)
		return nil, err
	}
	// yhy 创建一个劫持请求, 用于屏蔽某些请求, img、font
	// 	router := browser.HijackRequests()  // 会更改response返回 包内容(增加的替换的 js )， page.HijackRequests() 还是原样的输出
	router := page.HijackRequests()
	defer router.MustStop()

	// 劫持 html 和 js ，用于将<script>xxx</script>进行替换
	router.MustAdd("*", func(ctx *rod.Hijack) {
		// *.woff2 字体
		if ctx.Request.Type() == proto.NetworkResourceTypeFont {
			ctx.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		// 图片
		if ctx.Request.Type() == proto.NetworkResourceTypeImage {
			ctx.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}

		err = ctx.LoadResponse(http.DefaultClient, true)
		if err != nil {
			return
		}

		// 防止重复
		if _, ok := JieConf.Visited.Load(ctx.Request.URL().String()); ok {
			// URL 已经被替换过了，跳过
			return
		}
		JieConf.Visited.Store(ctx.Request.URL().String(), true)

		if ctx.Request.Type() == proto.NetworkResourceTypeDocument {
			go sensitive.Detection(ctx.Request.URL().String(), ctx.Response.Body())
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
			go sensitive.Detection(ctx.Request.URL().String(), body)
			convedBody, err := dom.HookParse(body)
			if err == nil {
				ctx.Response.SetBody(body + "\n" + convedBody)
			}
		}
	})
	go router.Run()

	pageRouter := NewHijack(page)
	pageRouter.SetPattern(&proto.FetchRequestPattern{
		URLPattern:   "*",
		RequestStage: proto.FetchRequestStageResponse,
	})
	go pageRouter.Start(func(e *proto.FetchRequestPaused) error {
		URL, _ := urlutil.Parse(e.Request.URL)
		body, _ := FetchGetResponseBody(page, e)
		headers := make(map[string][]string)
		for _, h := range e.ResponseHeaders {
			headers[h.Name] = []string{h.Value}
		}
		var (
			statusCode     int
			statucCodeText string
		)
		if e.ResponseStatusCode != nil {
			statusCode = *e.ResponseStatusCode
		}
		if e.ResponseStatusText != "" {
			statucCodeText = e.ResponseStatusText
		} else {
			statucCodeText = http.StatusText(statusCode)
		}
		httpreq, _ := http.NewRequest(e.Request.Method, URL.String(), strings.NewReader(e.Request.PostData))
		httpresp := &http.Response{
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			StatusCode:    statusCode,
			Status:        statucCodeText,
			Header:        headers,
			Body:          io.NopCloser(bytes.NewReader(body)),
			Request:       httpreq,
			ContentLength: int64(len(body)),
		}

		var rawBytesRequest, rawBytesResponse []byte
		if r, err := retryablehttp.FromRequest(httpreq); err == nil {
			rawBytesRequest, _ = r.Dump()
		} else {
			rawBytesRequest, _ = httputil.DumpRequestOut(httpreq, true)
		}
		rawBytesResponse, _ = httputil.DumpResponse(httpresp, true)

		bodyReader, _ := goquery.NewDocumentFromReader(bytes.NewReader(body))
		technologies := c.Options.Wappalyzer.Fingerprint(headers, body)
		resp := &navigation.Response{
			Resp:         httpresp,
			Body:         string(body),
			Reader:       bodyReader,
			Depth:        depth,
			RootHostname: s.Hostname,
			Technologies: mapsutil.GetKeys(technologies),
			StatusCode:   statusCode,
			Headers:      utils.FlattenHeaders(headers),
			Raw:          string(rawBytesResponse),
		}

		// trim trailing /
		normalizedheadlessURL := strings.TrimSuffix(e.Request.URL, "/")
		matchOriginalURL := stringsutil.EqualFoldAny(request.URL, e.Request.URL, normalizedheadlessURL)
		if matchOriginalURL {
			request.Raw = string(rawBytesRequest)
			response = resp
		}

		// process the raw response
		navigationRequests := parser.ParseResponse(resp)
		c.Enqueue(s.Queue, navigationRequests...)
		return FetchContinueRequest(page, e)
	})() //nolint
	defer func() {
		if err := pageRouter.Stop(); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}()

	timeout := time.Duration(c.Options.Options.Timeout) * time.Second
	page = page.Timeout(timeout)

	// todo 这里改一下 使用 PageLifecycleEventNameLoad ，而不是 PageLifecycleEventNameFirstMeaningfulPaint
	// 为什么？因为 当 使用 PageLifecycleEventNameFirstMeaningfulPaint 时，有些情况下比如空白页面，啥也没有，这种就会导致该页面发生超时错误,并且无法获取当前页面的 body 等信息，发生 panic
	// PageLifecycleEventNameLoad 会等待全部资源加载完成，比较耗时，
	// wait the page to be fully loaded and becoming idle
	waitNavigation := page.WaitNavigation(proto.PageLifecycleEventNameLoad)

	if err := page.Navigate(request.URL); err != nil {
		return nil, errorutil.NewWithTag("hybrid", "could not navigate target").Wrap(err)
	}

	waitNavigation()

	// Wait for the window.onload event
	if err := page.WaitLoad(); err != nil {
		gologger.Warning().Msgf("\"%s\" on wait load: %s\n", request.URL, err)
	}

	// wait for idle the network requests
	if err := page.WaitIdle(timeout); err != nil {
		gologger.Warning().Msgf("\"%s\" on wait idle: %s\n", request.URL, err)
	}

	var getDocumentDepth = int(-1)
	getDocument := &proto.DOMGetDocument{Depth: &getDocumentDepth, Pierce: true}
	result, err := getDocument.Call(page)
	if err != nil {
		return nil, errorutil.NewWithTag("hybrid", "could not get dom").Wrap(err)
	}
	var builder strings.Builder
	traverseDOMNode(result.Root, &builder)

	body, err := page.HTML()
	if err != nil {
		return nil, errorutil.NewWithTag("hybrid", "could not get html").Wrap(err)
	}
	parsed, err := urlutil.Parse(request.URL)
	if err != nil {
		return nil, errorutil.NewWithTag("hybrid", "url could not be parsed").Wrap(err)
	}

	if response.Resp == nil {
		response.Resp = &http.Response{Header: make(http.Header), Request: &http.Request{URL: parsed.URL}}
	} else {
		response.Resp.Request.URL = parsed.URL
	}

	// Create a copy of intrapolated shadow DOM elements and parse them separately
	responseCopy := *response
	responseCopy.Body = builder.String()

	responseCopy.Reader, _ = goquery.NewDocumentFromReader(strings.NewReader(responseCopy.Body))
	if responseCopy.Reader != nil {
		navigationRequests := parser.ParseResponse(&responseCopy)
		c.Enqueue(s.Queue, navigationRequests...)
	}

	response.Body = body

	response.Reader, err = goquery.NewDocumentFromReader(strings.NewReader(response.Body))
	if err != nil {
		return nil, errorutil.NewWithTag("hybrid", "could not parse html").Wrap(err)
	}
	return response, nil
}

// traverseDOMNode performs traversal of node completely building a pseudo-HTML
// from it including the Shadow DOM, Pseudo elements and other children.
//
// TODO: Remove this method when we implement human-like browser navigation
// which will anyway use browser APIs to find elements instead of goquery
// where they will have shadow DOM information.
func traverseDOMNode(node *proto.DOMNode, builder *strings.Builder) {
	buildDOMFromNode(node, builder)
	if node.TemplateContent != nil {
		traverseDOMNode(node.TemplateContent, builder)
	}
	if node.ContentDocument != nil {
		traverseDOMNode(node.ContentDocument, builder)
	}
	for _, children := range node.Children {
		traverseDOMNode(children, builder)
	}
	for _, shadow := range node.ShadowRoots {
		traverseDOMNode(shadow, builder)
	}
	for _, pseudo := range node.PseudoElements {
		traverseDOMNode(pseudo, builder)
	}
}

const (
	elementNode = 1
)

var knownElements = map[string]struct{}{
	"a": {}, "applet": {}, "area": {}, "audio": {}, "base": {}, "blockquote": {}, "body": {}, "button": {}, "embed": {}, "form": {}, "frame": {}, "html": {}, "iframe": {}, "img": {}, "import": {}, "input": {}, "isindex": {}, "link": {}, "meta": {}, "object": {}, "script": {}, "svg": {}, "table": {}, "video": {},
}

func buildDOMFromNode(node *proto.DOMNode, builder *strings.Builder) {
	if node.NodeType != elementNode {
		return
	}
	if _, ok := knownElements[node.LocalName]; !ok {
		return
	}
	builder.WriteRune('<')
	builder.WriteString(node.LocalName)
	builder.WriteRune(' ')
	if len(node.Attributes) > 0 {
		for i := 0; i < len(node.Attributes); i = i + 2 {
			builder.WriteString(node.Attributes[i])
			builder.WriteRune('=')
			builder.WriteString("\"")
			builder.WriteString(node.Attributes[i+1])
			builder.WriteString("\"")
			builder.WriteRune(' ')
		}
	}
	builder.WriteRune('>')
	builder.WriteString("</")
	builder.WriteString(node.LocalName)
	builder.WriteRune('>')
}
