package task

import (
	"fmt"
	"github.com/yhy0/Jie/crawler"
	"github.com/yhy0/Jie/crawler/katana/pkg/output"
	"github.com/yhy0/Jie/logging"
	"golang.org/x/net/publicsuffix"
	"net/url"
	"path"
	"strings"
)

/**
  @author: yhy
  @since: 2023/1/10
  @desc: 对爬虫/被动代理结果的处理
**/

type CrawlResult struct {
	URL      string
	Method   string
	Body     string
	Source   string
	Headers  map[string]string
	Path     string
	File     string
	Hostname string // 当前域名
	Rdn      string // 顶级域名
	Rurl     string
	Dir      string
	Kv       string
}

var storeFields = []string{"url", "path", "fqdn", "rdn", "rurl", "qurl", "qpath", "file", "kv", "dir", "udir"}

// Crawler 运行 Katana 爬虫
func (t *Task) Crawler() {
	// 获取结果
	outputWriter := output.NewMockOutputWriter()
	outputWriter.WriteCallback = func(result *output.Result) {
		// 对爬虫结果格式化
		var crawlResult CrawlResult
		crawlResult.StoreFields(result)
		crawlResult.Method = result.Method
		crawlResult.Body = result.Body
		crawlResult.Source = result.Source

		t.Input.Url = crawlResult.URL

		logging.Logger.Infof("URL: %s, Method: %s, Body: %s, Source: %s, Headers: %s, Path: %s, Hostname: %s, Rdn: %s, Rurl: %s, Dir: %s", crawlResult.URL, crawlResult.Method, crawlResult.Body, crawlResult.Source, crawlResult.Headers, crawlResult.Path, crawlResult.Hostname, crawlResult.Rdn, crawlResult.Rurl, crawlResult.Dir)

		t.CrawlResult = &crawlResult
		t.Distribution()
	}

	task := crawler.KatanaTask{
		Target:       []string{t.Input.Target},
		Proxy:        t.Input.Proxy,
		OutputWriter: outputWriter,
	}

	task.StartCrawler()

	outputWriter.Close()
}

// StoreFields stores fields for a result into individual files
// based on name.
func (c *CrawlResult) StoreFields(output *output.Result) {
	parsed, err := url.Parse(output.URL)
	if err != nil {
		return
	}

	hostname := parsed.Hostname()
	etld, _ := publicsuffix.EffectiveTLDPlusOne(hostname)
	rootURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	for _, field := range storeFields {
		c.getValueForField(output, parsed, hostname, etld, rootURL, field)
	}
}

// getValueForField returns value for a field
func (c *CrawlResult) getValueForField(output *output.Result, parsed *url.URL, hostname, rdn, rurl, field string) string {
	switch field {
	case "url":
		c.URL = output.URL
		return output.URL
	case "path":
		c.Path = parsed.Path
		return parsed.Path
	case "fqdn":
		c.Hostname = hostname
		return hostname
	case "rdn":
		c.Rdn = rdn
		return rdn
	case "rurl":
		c.Rurl = rurl
		return rurl
	case "file":
		basePath := path.Base(parsed.Path)
		if parsed.Path != "" && parsed.Path != "/" && strings.Contains(basePath, ".") {
			c.File = basePath
			return basePath
		}
	case "dir":
		if parsed.Path != "" && parsed.Path != "/" && strings.Contains(parsed.Path[1:], "/") {
			c.Dir = path.Dir(parsed.Path)
			return parsed.Path[:strings.LastIndex(parsed.Path[1:], "/")+2]
		}
	case "udir":
		if parsed.Path != "" && parsed.Path != "/" && strings.Contains(parsed.Path[1:], "/") {
			return fmt.Sprintf("%s%s", rurl, parsed.Path[:strings.LastIndex(parsed.Path[1:], "/")+2])
		}
	case "qpath":
		if len(parsed.Query()) > 0 {
			return fmt.Sprintf("%s?%s", parsed.Path, parsed.Query().Encode())
		}
	case "qurl":
		if len(parsed.Query()) > 0 {
			return parsed.String()
		}
	case "key":
		values := make([]string, 0, len(parsed.Query()))
		for k := range parsed.Query() {
			values = append(values, k)
		}
		return strings.Join(values, "\n")
	case "value":
		values := make([]string, 0, len(parsed.Query()))
		for _, v := range parsed.Query() {
			values = append(values, v...)
		}
		return strings.Join(values, "\n")
	case "kv":
		values := make([]string, 0, len(parsed.Query()))
		for k, v := range parsed.Query() {
			for _, value := range v {
				values = append(values, strings.Join([]string{k, value}, "="))
			}
		}
		c.Kv = strings.Join(values, "\n")
		return strings.Join(values, "\n")
	}
	return ""
}
