package task

import (
	"fmt"
	"github.com/remeh/sizedwaitgroup"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/crawler"
	"github.com/yhy0/Jie/crawler/katana/pkg/output"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
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

var storeFields = []string{"url", "path", "fqdn", "rdn", "rurl", "qurl", "qpath", "file", "kv", "dir", "udir"}

// Crawler 运行 Katana 爬虫
func (t *Task) Crawler() {
	t.wg = sizedwaitgroup.New(t.Parallelism)
	// 获取结果
	outputWriter := output.NewMockOutputWriter()
	outputWriter.WriteCallback = func(result *output.Result) {
		// 对爬虫结果格式化
		var crawlResult = &input.CrawlResult{
			Target:  t.Target,
			Method:  result.Method,
			Body:    result.Body,
			Source:  result.Source,
			Headers: result.Headers,
		}

		StoreFields(crawlResult, result)

		logging.Logger.Infof("[*Crawler] URL: %s, Method: %s, Body: %s, Source: %s, Headers: %s, Path: %s, Hostname: %s, Rdn: %s, Rurl: %s, Dir: %s", crawlResult.Url, crawlResult.Method, crawlResult.Body, crawlResult.Source, crawlResult.Headers, crawlResult.Path, crawlResult.Hostname, crawlResult.Rdn, crawlResult.RUrl, crawlResult.Dir)

		t.Distribution(crawlResult)
	}

	task := crawler.KatanaTask{
		Target:       []string{t.Target},
		Proxy:        conf.GlobalConfig.WebScan.Proxy,
		OutputWriter: outputWriter,
	}

	task.StartCrawler()

	outputWriter.Close()

	t.wg.Wait()
}

// StoreFields stores fields for a result into individual files
// based on name.
func StoreFields(c *input.CrawlResult, output *output.Result) {
	parsed, err := url.Parse(output.URL)
	if err != nil {
		return
	}

	hostname := parsed.Hostname()
	etld, _ := publicsuffix.EffectiveTLDPlusOne(hostname)
	rootURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	for _, field := range storeFields {
		getValueForField(c, output, parsed, hostname, etld, rootURL, field)
	}
}

// getValueForField returns value for a field
func getValueForField(c *input.CrawlResult, output *output.Result, parsed *url.URL, hostname, rdn, rurl, field string) string {
	switch field {
	case "url":
		c.Url = output.URL
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
		c.RUrl = rurl
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
		c.Param = values
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
