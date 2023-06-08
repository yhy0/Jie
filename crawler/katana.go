package crawler

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/crawler/katana/pkg/types"
	"github.com/yhy0/Jie/crawler/katana/pkg/utils/queue"
	"github.com/yhy0/logging"
	"strings"
)

/**
  @author: yhy
  @since: 2023/1/6
  @desc: 使用 github.com/projectdiscovery/katana/ 作为爬虫
**/

type KatanaTask struct {
	Target   string
	OnResult types.OnResultCallback
}

// 默认过滤的后缀名
var extensionFilter = []string{
	"css", "png", "gif", "jpg", "mp4", "mp3", "mng", "pct", "bmp", "jpeg", "pst", "psp", "ttf",
	"tif", "tiff", "ai", "drw", "wma", "ogg", "wav", "ra", "aac", "mid", "au", "aiff",
	"dxf", "eps", "ps", "svg", "3gp", "asf", "asx", "avi", "mov", "mpg", "qt", "rm",
	"wmv", "m4a", "bin", "xls", "xlsx", "ppt", "pptx", "doc", "docx", "odt", "ods", "odg",
	"odp", "exe", "zip", "rar", "tar", "gz", "iso", "rss", "pdf", "dll", "ico",
	"gz2", "apk", "crt", "woff", "map", "woff2", "webp", "less", "dmg", "bz2", "otf", "swf",
	"flv", "mpeg", "dat", "xsl", "csv", "cab", "exif", "wps", "m4v", "rmvb",
}

var Katana *Runner

// NewKatana 初始化 katana 爬虫，全局只初始化一次，共用一个，不然创建多次，时间长了，目标多了，小水管受不了
func NewKatana(show bool) {
	if !conf.GlobalConfig.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	options := &types.Options{
		MaxDepth:                  10,                              // 最大页面深度限制
		ScrapeJSResponses:         true,                            // 启用 JavaScript 文件解析 + 抓取在 JavaScript 文件中发现的端点的选项
		CrawlDuration:             0,                               // 爬取目标的最长持续时间
		KnownFiles:                "all",                           // 启用对已知文件的爬取(all、robots.txt、sitemap.xml)
		BodyReadSize:              2 * 1024 * 1024,                 // 读取响应的最大大小
		Timeout:                   30,                              // 请求超时时间
		AutomaticFormFill:         true,                            // 启用自动表单填充(实验性)
		Retries:                   0,                               // 重试次数
		Strategy:                  queue.DepthFirst.String(),       // 深度优先
		Proxy:                     conf.GlobalConfig.WebScan.Proxy, // http/socks5 代理
		CustomHeaders:             []string{},                      // 自定义请求头
		FormConfig:                "",                              // 表单配置文件
		Headless:                  true,                            // 是否使用无头浏览器
		UseInstalledChrome:        false,                           // 是否使用已安装的 Chrome, 否则会自动下载 Chrome
		ShowBrowser:               show,                            // 显示浏览器
		HeadlessOptionalArguments: nil,                             // 无头浏览器可选参数
		HeadlessNoSandbox:         true,                            // 是否以 --no-sandbox 模式启动 Chrome
		Scope:                     nil,                             // 爬取的域名范围的url正则表达式
		OutOfScope:                nil,                             // 不在爬取范围内的url正则表达式
		// rdn: 爬取范围为根域名和所有子域(默认), dn:搜索范围为域名关键字 fqdn:爬取范围为给定子(域)
		FieldScope:      "rdn",                                                          // 默认域名范围的字段(dn、rdn、fqdn)
		NoScope:         false,                                                          // 禁用域名范围
		DisplayOutScope: false,                                                          // 显示不在爬取范围内的url
		Fields:          "url,path,fqdn,rdn,rurl,qurl,qpath,file,key,value,kv,dir,udir", // 输出显示的字段
		StoreFields:     "",                                                             // 输出存储的字段
		ExtensionsMatch: nil,                                                            // 匹配给定扩展名的输出(例如-em php、html、js)
		ExtensionFilter: extensionFilter,                                                // 过滤给定扩展名的输出(例如-ef png,css)
		Concurrency:     10,                                                             // 每个目标同时获取的 url 数量
		Parallelism:     10,                                                             // 同时处理的目标数量
		Delay:           0,                                                              // 每次请求之间的请求延迟(以秒为单位)
		RateLimit:       150,                                                            // 每秒发送的最大请求数
		RateLimitMinute: 0,                                                              // 每分钟发送的最大请求数
		OutputFile:      "",                                                             // 输出文件
		JSON:            false,                                                          // 输出为 json 格式
		NoColors:        false,                                                          // 禁用颜色
		Silent:          !conf.GlobalConfig.Debug,                                       // 禁用输出
		Verbose:         conf.GlobalConfig.Debug,                                        // 显示详细信息
		Version:         false,                                                          // 显示版本信息
	}

	var err error
	Katana, err = New(options)

	if err != nil || Katana == nil {
		logging.Logger.Fatalf("could not create runner: %s", err)
	}
}

func (t *KatanaTask) StartCrawler() {
	Katana.Options.OnResult = t.OnResult

	target := strings.TrimSpace(t.Target)
	target = addSchemeIfNotExists(target)

	if err := Katana.Crawler.Crawl(target); err != nil {
		logging.Logger.Warnf("Could not crawl %s: %s", target, err)
	}
}

// scheme less urls are skipped and are required for headless mode and other purposes
// this method adds scheme if given input does not have any
func addSchemeIfNotExists(inputURL string) string {
	if strings.HasPrefix(inputURL, urlutil.HTTP) || strings.HasPrefix(inputURL, urlutil.HTTPS) {
		return inputURL
	}
	parsed, err := urlutil.Parse(inputURL)
	if err != nil {
		gologger.Warning().Msgf("input %v is not a valid url got %v", inputURL, err)
		return inputURL
	}
	if parsed.Port() != "" && (parsed.Port() == "80" || parsed.Port() == "8080") {
		return urlutil.HTTP + urlutil.SchemeSeparator + inputURL
	} else {
		return urlutil.HTTPS + urlutil.SchemeSeparator + inputURL
	}
}
