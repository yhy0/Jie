package task

import (
	"encoding/json"
	"github.com/remeh/sizedwaitgroup"
	"github.com/yhy0/Jie/crawler"
	"github.com/yhy0/Jie/crawler/crawlergo"
	"github.com/yhy0/Jie/crawler/crawlergo/config"
	"github.com/yhy0/Jie/crawler/crawlergo/model"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/scan/fuzz/traversal"
	"github.com/yhy0/logging"
	"strings"
	"sync"
	"time"
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

// 默认过滤的后缀名
var extensionFilter = []string{
	".css", ".js", ".ico", ".ttf",
}

// Crawler 运行爬虫
func (t *Task) Crawler(waf []string) ([]string, []string) {
	t.wg = sizedwaitgroup.New(t.Parallelism)
	t.limit = make(chan struct{}, t.Parallelism)

	var targets []*model.Request

	var req model.Request
	url, err := model.GetUrl(t.Target)
	if err != nil {
		logging.Logger.Error("parse url failed, ", err)
		return nil, nil
	}

	req = model.GetRequest(config.GET, url, getOption())
	req.Proxy = crawler.TaskConfig.Proxy
	targets = append(targets, &req)

	if len(targets) != 0 {
		logging.Logger.Infof("Init crawler task, host: %s, max tab count: %d, max crawl count: %d, max runtime: %ds",
			targets[0].URL.Host, crawler.TaskConfig.MaxTabsCount, crawler.TaskConfig.MaxCrawlCount, crawler.TaskConfig.MaxRunTime)
		//logging.Logger.Info("filter mode: ", crawler.TaskConfig.FilterMode)
	} else {
		logging.Logger.Errorln("no validate target.")
		return nil, nil
	}

	if crawler.TaskConfig.Proxy != "" {
		logging.Logger.Info("request with proxy: ", crawler.TaskConfig.Proxy)
	}

	// 获取爬虫 url 中所有的 path
	var dirs []string

	var l sync.Mutex
	// 实时获取结果
	onResult := func(result *crawlergo.OutResult) {
		if result.ReqList.URL.Path != "" && result.ReqList.URL.Path != "/" {
			l.Lock()
			dirs = append(dirs, result.ReqList.URL.Path)
			l.Unlock()
		}
		// 不对这些进行漏扫
		for _, suffix := range extensionFilter {
			if strings.HasSuffix(result.ReqList.URL.String(), suffix) {
				return
			}
		}
		logging.Logger.Infof("[result]: %v ", result.ReqList.URL.String())

		resp, err := httpx.Request(result.ReqList.URL.String(), result.ReqList.Method, result.ReqList.PostData, false, nil)
		if err != nil {
			return
		}

		// 对爬虫结果格式化
		var crawlResult = &input.CrawlResult{
			Target:                t.Target,
			Method:                result.ReqList.Method,
			Source:                result.ReqList.Source,
			Headers:               make(map[string]string),
			RequestBody:           "",
			Waf:                   waf,
			IsSensorServerEnabled: true,
			Resp:                  resp,
		}

		crawlResult.Url = strings.ReplaceAll(result.ReqList.URL.String(), "\\n", "")
		crawlResult.Url = strings.ReplaceAll(crawlResult.Url, "\\t", "")
		crawlResult.Url = strings.ReplaceAll(crawlResult.Url, "\\n", "")

		//logging.Logger.Infof("[Processing] %s [%s] %s", crawlResult.Method, crawlResult.Url, crawlResult.Source)
		t.Distribution(crawlResult)
	}

	// 开始爬虫任务
	task, err := crawlergo.NewCrawlerTask(targets, crawler.TaskConfig, onResult)
	if err != nil {
		logging.Logger.Error("create crawler task failed.")
		return nil, nil
	}

	task.Browser = crawler.Browser

	task.Run()

	logging.Logger.Infof("Task finished, %d results, %d subdomains found, runtime: %d",
		len(task.Result.ReqList), len(task.Result.SubDomainList), time.Now().Unix()-task.Start.Unix())

	t.wg.Wait()

	traversal.NginxAlias(t.Target, "", dirs)

	return task.Result.SubDomainList, dirs
}

func getOption() model.Options {
	var option model.Options

	if crawler.TaskConfig.ExtraHeadersString != "" {
		err := json.Unmarshal([]byte(crawler.TaskConfig.ExtraHeadersString), &crawler.TaskConfig.ExtraHeaders)
		if err != nil {
			logging.Logger.Fatal("custom headers can't be Unmarshal.")
			panic(err)
		}
		option.Headers = crawler.TaskConfig.ExtraHeaders
	}
	return option
}
