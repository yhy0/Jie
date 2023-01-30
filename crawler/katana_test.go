package crawler

import (
	"github.com/yhy0/Jie/crawler/katana/pkg/output"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/task"
	"testing"
)

/**
  @author: yhy
  @since: 2023/1/6
  @desc: //TODO
**/

func TestKatana(t *testing.T) {

	// 获取结果
	outputWriter := output.NewMockOutputWriter()
	/*	type Result struct {
			Timestamp time.Time `json:"timestamp,omitempty"`  	时间戳
			Method string `json:"method,omitempty"` 		  	请求方法
			Body string `json:"body,omitempty"`					返回的body
			URL string `json:"endpoint,omitempty"`				获取到的 url
			Source string `json:"source,omitempty"`				来源
			Tag string `json:"tag,omitempty"`					标签: file, a, link
			Attribute string `json:"attribute,omitempty"`		属性 ，该链接是从哪里获取的，如 robots.txt, href
		}
	*/

	//var crawlResults []task.CrawlResult
	outputWriter.WriteCallback = func(result *output.Result) {
		var crawlResult task.CrawlResult
		crawlResult.StoreFields(result)

		crawlResult.Method = result.Method
		crawlResult.Body = result.Body
		crawlResult.Source = result.Source
		//crawlResults = append(crawlResults, crawlResult)

		logging.Logger.Infof("URL: %s, Method: %s, Body: %s, Source: %s, Headers: %s, Path: %s, Hostname: %s, Rdn: %s, Rurl: %s, Dir: %s", crawlResult.URL, crawlResult.Method, crawlResult.Body, crawlResult.Source, crawlResult.Headers, crawlResult.Path, crawlResult.Hostname, crawlResult.Rdn, crawlResult.Rurl, crawlResult.Dir)

	}

	task := KatanaTask{
		Target:       []string{"https://moresec.cn/"},
		Proxy:        "",
		OutputWriter: outputWriter,
	}
	task.StartCrawler()

	outputWriter.Close()
}
