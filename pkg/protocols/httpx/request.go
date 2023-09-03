package httpx

import (
	"bytes"
	"crypto/tls"
	"github.com/corpix/uarand"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/logging"
	"go.uber.org/ratelimit"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

/**
  @author: yhy
  @since: 2022/6/1
  @desc: //TODO
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

type Session struct {
	// Client is the current http client
	Client *http.Client
	// Rate limit instance
	RateLimiter ratelimit.Limiter // 每秒请求速率限制
}

var session *Session

// DefaultResolvers contains the default list of resolvers known to be good
var DefaultResolvers = []string{
	"1.1.1.1",         // Cloudflare
	"1.0.0.1",         // Cloudlfare secondary
	"8.8.8.8",         // Google
	"8.8.4.4",         // Google secondary
	"223.5.5.5",       // AliDNS
	"223.6.6.6",       // AliDNS
	"119.29.29.29",    // DNSPod
	"114.114.114.114", // 114DNS
	"114.114.115.115", // 114DNS
}

func NewSession(rateLimit ...int) {
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	fastdialerOpts.WithDialerHistory = true

	fastdialerOpts.BaseResolvers = DefaultResolvers

	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		logging.Logger.Fatalf("could not create resolver cache: %s", err)
	}

	Transport := &http.Transport{
		DialContext:         dialer.Dial,
		DialTLSContext:      dialer.DialTLS,
		MaxIdleConnsPerHost: -1,
		DisableKeepAlives:   true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
	// Add proxy
	if conf.GlobalConfig.Options.Proxy != "" {
		proxyURL, _ := url.Parse(conf.GlobalConfig.Options.Proxy)
		if isSupportedProtocol(proxyURL.Scheme) {
			Transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			logging.Logger.Warnln("Unsupported proxy protocol: %s", proxyURL.Scheme)
		}
	}

	client := &http.Client{
		Transport: Transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	session = &Session{
		Client: client,
	}

	if len(rateLimit) == 0 {
		rateLimit = append(rateLimit, 20)
	}
	// Initiate rate limit instance
	session.RateLimiter = ratelimit.New(rateLimit[0])
}

func RequestBasic(username string, password string, target string, method string, postdata string, isredirect bool, headers map[string]string) (*Response, error) {
	if isredirect {
		jar, _ := cookiejar.New(nil)
		session.Client.Jar = jar
	}

	req, err := http.NewRequest(strings.ToUpper(method), target, strings.NewReader(postdata))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "close")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	flag := true
	for v, k := range headers {
		if k == "Content-Type" {
			flag = false
		}
		req.Header[v] = []string{k}
	}

	if flag {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	}

	requestDump, _ := httputil.DumpRequestOut(req, true)

	session.RateLimiter.Take()
	resp, err := session.Client.Do(req)
	if err != nil {
		//防止空指针
		return &Response{"999", 999, "", "", "", nil, 0, "", "", 0}, err
	}
	defer resp.Body.Close()

	dump, _ := httputil.DumpResponse(resp, false)

	var location string
	var respbody string
	if body, err := ioutil.ReadAll(resp.Body); err == nil {
		respbody = string(body)
	}

	responseDump := string(dump) + respbody

	if resplocation, err := resp.Location(); err == nil {
		location = resplocation.String()
	}

	return &Response{resp.Status, resp.StatusCode, respbody, string(requestDump), responseDump, resp.Header, int(resp.ContentLength), resp.Request.URL.String(), location, 0}, nil
}

func Get(target string) (*Response, error) {
	return Request(target, "GET", "", false, nil)
}

func Request(target string, method string, postdata string, isredirect bool, headers map[string]string) (*Response, error) {
	if isredirect {
		jar, _ := cookiejar.New(nil)
		session.Client.Jar = jar
	}

	req, err := http.NewRequest(strings.ToUpper(method), target, strings.NewReader(postdata))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "close")
	flag := true
	for k, v := range headers {
		if k == "Content-Type" {
			flag = false
		}
		req.Header[k] = []string{v}
	}

	if flag {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	}

	var start = time.Now()
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	requestDump, _ := httputil.DumpRequestOut(req, true)
	session.RateLimiter.Take()
	resp, err := session.Client.Do(req)
	if err != nil {
		//防止空指针
		return &Response{"999", 999, "", "", "", nil, 0, "", "", 0}, err
	}
	defer resp.Body.Close()

	//TODOs 换成其他请求方法重试
	if funk.Contains(resp.Status, "Method Not Allowed") {
		if strings.ToUpper(method) == "GET" {
			response, err := Request(target, "POST", postdata, isredirect, headers)
			if err != nil {
				return nil, err
			}
			return response, nil
		}
	}

	dump, _ := httputil.DumpResponse(resp, false)

	var location string
	var respbody string
	if body, err := ioutil.ReadAll(resp.Body); err == nil {
		respbody = string(body)
	}

	responseDump := string(dump) + respbody
	if resplocation, err := resp.Location(); err == nil {
		location = resplocation.String()
	}

	if resp.StatusCode == 200 {
		// 检查一下是否为 js 控制的跳转
		if checkJSRedirect(respbody) {
			resp.StatusCode = 302
		}
	}

	return &Response{resp.Status, resp.StatusCode, respbody, string(requestDump), responseDump, resp.Header, int(resp.ContentLength), resp.Request.URL.String(), location, float64(time.Since(start).Milliseconds())}, nil
}

// UploadRequest 新建上传请求
func UploadRequest(target string, params map[string]string, name, path string) (*Response, error) {
	body := &bytes.Buffer{}                                       // 初始化body参数
	writer := multipart.NewWriter(body)                           // 实例化multipart
	part, err := writer.CreateFormFile(name, filepath.Base(path)) // 创建multipart 文件字段
	if err != nil {
		return nil, err
	}

	_, err = part.Write([]byte("test")) // 写入文件数据到multipart
	if err != nil {
		return nil, err
	}

	for key, val := range params {
		_ = writer.WriteField(key, val) // 写入body中额外参数
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", target, body) // 新建请求
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Content-Type", writer.FormDataContentType()) // 设置请求头,!!!非常重要，否则远端无法识别请求
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "close")

	requestDump, _ := httputil.DumpRequestOut(req, true)

	session.RateLimiter.Take()

	resp, err := session.Client.Do(req)
	if err != nil {
		//防止空指针
		return &Response{"999", 999, "", "", "", nil, 0, "", "", 0}, err
	}

	dump, _ := httputil.DumpResponse(resp, false)

	var location string
	var respbody string
	defer resp.Body.Close()
	if rbody, err := ioutil.ReadAll(resp.Body); err == nil {
		respbody = string(rbody)
	}

	responseDump := string(dump) + respbody
	if resplocation, err := resp.Location(); err == nil {
		location = resplocation.String()
	}

	return &Response{resp.Status, resp.StatusCode, respbody, string(requestDump), responseDump, resp.Header, int(resp.ContentLength), resp.Request.URL.String(), location, 0}, nil
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
