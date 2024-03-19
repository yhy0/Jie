package httpx

import (
    "bufio"
    "bytes"
    "errors"
    "fmt"
    "github.com/imroc/req/v3"
    regexp "github.com/wasilibs/go-re2"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/scan/gadget/sensitive"
    "github.com/yhy0/logging"
    "go.uber.org/ratelimit"
    "io/ioutil"
    "net"
    "net/http"
    "net/http/httputil"
    "net/url"
    "runtime"
    "strings"
    "time"
)

/**
   @author yhy
   @since 2023/11/22
   @desc //TODO
**/

type Response struct {
    Status           string
    StatusCode       int
    Body             string
    RequestDump      string
    ResponseDump     string
    Header           http.Header
    ContentLength    int
    RequestUrl       string
    Location         string
    ServerDurationMs float64 // 服务器响应时间
}

type Options struct {
    Timeout         int
    RetryTimes      int    // 重定向次数 0 为不重试
    VerifySSL       bool   // default false
    AllowRedirect   int    // default false
    Proxy           string // proxy settings, support http/https proxy only, e.g. http://127.0.0.1:8080
    QPS             int    // 每秒最大请求数
    MaxConnsPerHost int    // 每个 host 最大连接数
    Headers         map[string]string
}

type Client struct {
    Client      *req.Client
    Options     *Options
    RateLimiter ratelimit.Limiter // 每秒请求速率限制
}

func NewClient(o *Options) *Client {
    if o == nil {
        o = &Options{
            Timeout:         conf.GlobalConfig.Http.Timeout,
            VerifySSL:       conf.GlobalConfig.Http.VerifySSL,
            RetryTimes:      conf.GlobalConfig.Http.RetryTimes,
            AllowRedirect:   conf.GlobalConfig.Http.AllowRedirect,
            Proxy:           conf.GlobalConfig.Http.Proxy,
            QPS:             conf.GlobalConfig.Http.MaxQps,
            MaxConnsPerHost: conf.GlobalConfig.Http.MaxConnsPerHost,
            Headers:         conf.GlobalConfig.Http.Headers,
        }
    }
    
    client := &Client{}
    /*
       Req 同时支持 HTTP/1.1，HTTP/2 和 HTTP/3，如果服务端支持，默认情况下首选 HTTP/2，其次 HTTP/1.1，这是由 TLS 握手协商的。
       如果启用了 HTTP3 (EnableHTTP3)，当探测到服务端支持 HTTP3，会使用 HTTP3 协议进行请求。
    */
    c := req.C().
        SetUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36").
        // SetCommonContentType("application/x-www-form-urlencoded; charset=utf-8").
        SetTimeout(time.Duration(o.Timeout) * time.Second)
    
    // https://github.com/imroc/req/issues/272
    if conf.GlobalConfig.Http.ForceHTTP1 {
        c.EnableForceHTTP1()
    } else {
        c.ImpersonateChrome() // 模拟Chrome浏览器, 不能和 EnableForceXXXX() 同时使用
    }
    
    c.SetMaxConnsPerHost(o.MaxConnsPerHost)
    c.SetMaxIdleConns(o.MaxConnsPerHost)
    
    // Add proxy
    if o.Proxy != "" {
        logging.Logger.Infoln("use proxy:", o.Proxy)
        proxyURL, _ := url.Parse(o.Proxy)
        if isSupportedProtocol(proxyURL.Scheme) {
            c.SetProxy(http.ProxyURL(proxyURL))
        } else {
            logging.Logger.Warnln("Unsupported proxy protocol: %s", proxyURL.Scheme)
        }
    }
    
    if !o.VerifySSL {
        c.EnableInsecureSkipVerify()
    }
    
    if o.RetryTimes > 0 {
        c.SetCommonRetryCount(o.RetryTimes).
            SetCommonRetryBackoffInterval(1*time.Second, 5*time.Second)
    }
    
    if o.QPS == 0 {
        o.QPS = conf.GlobalConfig.Http.MaxQps
    }
    // Initiate rate limit instance
    client.RateLimiter = ratelimit.New(o.QPS)
    
    client.Client = c
    client.Options = o
    return client
}

func (c *Client) Basic(target string, method string, body string, header map[string]string, username, password string) (*Response, error) {
    c.Client.SetCommonBasicAuth(username, password)
    return c.Request(target, method, body, header)
}

func (c *Client) Request(target string, method string, body string, header map[string]string) (*Response, error) {
    method = strings.ToUpper(method)
    
    // https://req.cool/docs/tutorial/debugging/
    var requestDumpBuf, responseDumpBuf bytes.Buffer
    
    // Enable dump with fully customized settings at client level.
    opt := &req.DumpOptions{
        RequestOutput:  &requestDumpBuf,
        ResponseOutput: &responseDumpBuf,
        RequestHeader:  true,
        RequestBody:    true,
        ResponseHeader: true,
        ResponseBody:   true,
        Async:          false,
    }
    
    // 重定向
    if c.Options.AllowRedirect == 0 {
        c.Client.SetRedirectPolicy(req.NoRedirectPolicy())
    } else {
        c.Client.SetRedirectPolicy(
            // Only allow up to 5 redirects
            req.MaxRedirectPolicy(c.Options.AllowRedirect),
            // Only allow redirect to same domain.
            // e.g. redirect "www.imroc.cc" to "imroc.cc" is allowed, but "google.com" is not
            req.SameDomainRedirectPolicy(),
        )
    }
    // 防止出现一些错误，这次重定向后，修改回去
    c.Options.AllowRedirect = 0
    
    request := c.Client.R().SetDumpOptions(opt).EnableDump().EnableTrace() // 启用 trace，获取响应的时间
    
    if c.Options.Headers != nil {
        if c.Options.Headers["Accept-Encoding"] == "gzip, deflate" {
            delete(c.Options.Headers, "Accept-Encoding")
        }
        request.SetHeaders(c.Options.Headers)
    }
    if header != nil {
        // https://github.com/imroc/req/issues/178#issuecomment-1282086128
        if header["Accept-Encoding"] == "gzip, deflate" {
            delete(header, "Accept-Encoding")
        }
        request.SetHeaders(header)
    }
    
    c.RateLimiter.Take()
    var resp *req.Response
    var err error
    if method == "GET" {
        resp, err = request.Get(target)
    } else if method == "HEAD" {
        resp, err = request.Head(target)
    } else if method == "OPTIONS" {
        resp, err = request.Options(target)
    } else if method == "POST" {
        resp, err = request.
            SetBody(body).
            Post(target)
    } else if method == "PUT" {
        resp, err = request.
            SetBody(body).
            Put(target)
    } else {
        logging.Logger.Warningf("Unsupported method: %s", method)
        return nil, errors.New(fmt.Sprintf("Unsupported method: %s", method))
    }
    
    if err != nil {
        return nil, err
    }
    
    var (
        location string
        respBody string
    )
    
    if respLocation, err := resp.Location(); err == nil {
        location = respLocation.String()
    }
    
    if respBodyByte, err := ioutil.ReadAll(resp.Body); err == nil {
        respBody = string(respBodyByte)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == 200 {
        // 检查一下是否为 js 控制的跳转
        if checkJSRedirect(respBody) {
            resp.StatusCode = 302
        }
    }
    
    // 检测所有的返回包，可能有某个插件导致报错，存在报错信息
    sensitive.PageErrorMessageCheck(target, requestDumpBuf.String(), respBody)
    
    return &Response{
        Status:           resp.Status,
        StatusCode:       resp.StatusCode,
        Body:             respBody,
        RequestDump:      requestDumpBuf.String(),
        ResponseDump:     responseDumpBuf.String(),
        Header:           resp.Header,
        ContentLength:    int(resp.ContentLength),
        RequestUrl:       resp.Request.URL.String(),
        Location:         location,
        ServerDurationMs: float64(request.TraceInfo().FirstResponseTime.Milliseconds()),
    }, nil
}

func (c *Client) Upload(target string, params map[string]string, name, fileName string) (*Response, error) {
    // https://req.cool/docs/tutorial/debugging/
    var requestDumpBuf, responseDumpBuf bytes.Buffer
    // Enable dump with fully customized settings at client level.
    opt := &req.DumpOptions{
        RequestOutput:  &requestDumpBuf,
        ResponseOutput: &responseDumpBuf,
        RequestHeader:  true,
        RequestBody:    true,
        ResponseHeader: true,
        ResponseBody:   true,
        Async:          false,
    }
    
    request := c.Client.R().SetDumpOptions(opt).EnableDump().
        SetHeaders(c.Options.Headers).
        EnableTrace() // 启用 trace，获取响应的时间
    
    var resp *req.Response
    var err error
    
    request.
        SetFileBytes(name, fileName, []byte("test")). // 文件名，文件内容
        SetFormData(params) // 写入body中额外参数
    
    if c.Options.Headers != nil {
        if c.Options.Headers["Accept-Encoding"] == "gzip, deflate" {
            delete(c.Options.Headers, "Accept-Encoding")
        }
        request.SetHeaders(c.Options.Headers)
    }
    
    resp, err = request.Post(target)
    
    if err != nil {
        return nil, err
    }
    
    var (
        location string
        respBody string
    )
    
    if respLocation, err := resp.Location(); err == nil {
        location = respLocation.String()
    }
    
    if respBodyByte, err := ioutil.ReadAll(resp.Body); err == nil {
        respBody = string(respBodyByte)
    }
    defer resp.Body.Close()
    
    c.RateLimiter.Take()
    
    return &Response{
        Status:           resp.Status,
        StatusCode:       resp.StatusCode,
        Body:             respBody,
        RequestDump:      requestDumpBuf.String(),
        ResponseDump:     responseDumpBuf.String(),
        Header:           resp.Header,
        ContentLength:    int(resp.ContentLength),
        RequestUrl:       resp.Request.URL.String(),
        Location:         location,
        ServerDurationMs: float64(request.TraceInfo().FirstResponseTime.Milliseconds()),
    }, nil
}

func checkJSRedirect(htmlStr string) bool {
    redirectPatterns := []string{
        `window\.location\.href\s*=\s*['"][^'"]+['"]`,
        `window\.location\.assign\(['"][^'"]+['"]\)`,
        `window\.location\.replace\(['"][^'"]+['"]\)`,
        `window\.history\.(?:back|forward|go)\(`,
        `(?:setTimeout|setInterval)\([^,]+,\s*\d+\)`,
        `(?:onclick|onmouseover)\s*=\s*['"][^'"]+['"]`,
        `addEventListener\([^,]+,\s*function`,
        `(?ms)<a id="a-link"></a>\s*<script>\s*localStorage\.x5referer.*?document\.getElementById`,
    }
    
    for _, pattern := range redirectPatterns {
        re := regexp.MustCompile(pattern)
        if re.MatchString(htmlStr) {
            return true
        }
    }
    return false
}

// Request10 发送 http/1.0
func Request10(host, raw string) (*Response, error) {
    defer func() {
        if err := recover(); err != nil {
            logging.Logger.Errorln("Request10 err:", err)
            debugStack := make([]byte, 1024)
            runtime.Stack(debugStack, false)
            logging.Logger.Errorf("Request10 Stack Trace:%v", string(debugStack))
        }
    }()
    conn, err := net.Dial("tcp", host)
    if err != nil {
        logging.Logger.Errorln("Error connecting:", err)
        return nil, err
    }
    defer conn.Close()
    // 发送请求
    _, err = fmt.Fprint(conn, raw)
    if err != nil {
        logging.Logger.Errorln("Error sending request:", err)
        return nil, err
    }
    
    // 读取响应
    reader := bufio.NewReader(conn)
    resp, err := http.ReadResponse(reader, nil)
    if err != nil {
        logging.Logger.Errorln("Error reading response:", err)
        return nil, err
    }
    defer resp.Body.Close()
    
    // 读取响应内容
    responseDump, _ := httputil.DumpResponse(resp, true)
    
    defer resp.Body.Close()
    
    // return &Response{
    //     resp.Status,
    //     resp.StatusCode,
    //     respBody,
    //     raw,
    //     string(responseDump),
    //     resp.Header,
    //     int(resp.ContentLength),
    //     resp.Request.URL.String(),
    //     location,
    //     0,
    // }, nil
    return &Response{
        RequestDump:  raw,
        ResponseDump: string(responseDump),
    }, nil
}

func Request(target string, method string, body string, header map[string]string) (*Response, error) {
    return NewClient(nil).Request(target, method, body, header)
}

func Get(target string) (*Response, error) {
    return NewClient(nil).Request(target, "GET", "", nil)
}
