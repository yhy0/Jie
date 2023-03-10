package task

import (
	"fmt"
	"github.com/remeh/sizedwaitgroup"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/crawler"
	"github.com/yhy0/Jie/crawler/katana/pkg/output"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
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

// 用于比较爬虫结果是否相同 todo 还要考虑到 json 的情况，以及其他的情况，去重的还不完美
type res struct {
	url    string
	method string
	param  string // 参数名
	body   string // 请求体
}

// Crawler 运行 Katana 爬虫
func (t *Task) Crawler(waf []string) {
	t.wg = sizedwaitgroup.New(t.Parallelism)

	fingerprints := make([]string, 0)

	single := make(map[string][]res)

	// todo 目前无头模式下不能获取 响应信息，尝试更改，但是响应还是有问题，等官方的看看，目前解决方案是，使用 http 请求一次
	// 获取结果
	outputWriter := output.NewMockOutputWriter()
	outputWriter.WriteCallback = func(result *output.Result) {
		// 对爬虫结果格式化
		var crawlResult = &input.CrawlResult{
			Target:      t.Target,
			Method:      result.Method,
			Source:      result.Source,
			Headers:     make(map[string]string),
			RequestBody: result.Body,
			Waf:         waf,
		}

		fingerprints = append(fingerprints, result.SourceTechnologies...)
		StoreFields(crawlResult, result)

		tempUrl := strings.Split(crawlResult.Url, "?")[0]

		value, ok := single[tempUrl]
		// 去重 http://testphp.vulnweb.com/artists.php?artist=1  http://testphp.vulnweb.com/artists.php?artist=2 ，这种扫描一次就行
		var flag = false
		if !ok {
			// 不存在, 直接加入
			single[tempUrl] = []res{{
				url:    tempUrl,
				method: crawlResult.Method,
				param:  strings.Join(crawlResult.Param, " "),
				body:   crawlResult.RequestBody,
			}}
			flag = true

		} else { // 存在，判断结构体是否相同
			for _, v := range value {
				if v.method == crawlResult.Method && v.param == strings.Join(crawlResult.Param, " ") && v.body == crawlResult.RequestBody {
					flag = false
					// 相同，不处理
					break
				} else {
					// 不同，加入
					single[tempUrl] = append(single[tempUrl], res{
						url:    tempUrl,
						method: crawlResult.Method,
						param:  strings.Join(crawlResult.Param, " "),
						body:   crawlResult.RequestBody,
					})
					flag = true
					break
				}
			}
		}

		if flag {
			resp, err := httpx.Request(result.URL, result.Method, result.Body, false, crawlResult.Headers)
			if err != nil {
				logging.Logger.Errorf("[Crawler] %s", err)
			} else {
				// 响应为 200 的才会进行扫描
				if resp.StatusCode == 200 {
					crawlResult.Resp = resp
					//logging.Logger.Infof("[*Crawler] URL: %s, Method: %s, Body: %s, Source: %s, Headers: %s, Path: %s, Hostname: %s, Rdn: %s, Rurl: %s, Dir: %s", crawlResult.Url, crawlResult.Method, crawlResult.RequestBody, crawlResult.Source, crawlResult.Headers, crawlResult.Path, crawlResult.Hostname, crawlResult.Rdn, crawlResult.RUrl, crawlResult.Dir)
					logging.Logger.Infof("[Processing] %s %s ", crawlResult.Method, crawlResult.Url)
					t.Distribution(crawlResult)
				} else {
					logging.Logger.Debugf("[Crawler] URL: %s Status: %d", crawlResult.Url, resp.StatusCode)
				}

			}
		}
	}

	task := crawler.KatanaTask{
		Target:       []string{t.Target},
		Proxy:        conf.GlobalConfig.WebScan.Proxy,
		OutputWriter: outputWriter,
	}

	task.StartCrawler()

	outputWriter.Close()

	t.wg.Wait()

	t.Fingerprints = funk.UniqString(fingerprints)

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
