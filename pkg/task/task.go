package task

import (
	"github.com/remeh/sizedwaitgroup"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/scan/brute"
	"github.com/yhy0/Jie/scan/cmdinject"
	"github.com/yhy0/Jie/scan/crlf"
	"github.com/yhy0/Jie/scan/jsonp"
	"github.com/yhy0/Jie/scan/sqlInjection"
	"github.com/yhy0/Jie/scan/ssrf"
	"github.com/yhy0/Jie/scan/xss"
	"github.com/yhy0/Jie/scan/xxe"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: TODO  后期看看有没有必要设计成插件式的，自我感觉没必要，还不如这样写，逻辑简单易懂
  		 todo 漏洞检测逻辑有待优化
**/

type Task struct {
	TaskId        string
	Target        string
	Fingerprints  []string
	PassiveResult string // todo 被动代理模式，需要考虑到重复数据的问题，防止重复发payload
	Parallelism   int    // 一个网站同时扫描的最大 url 个数
	Single        bool   // 像 poc 等任务扫描，一个网站应该只运行一次扫描任务
	wg            sizedwaitgroup.SizedWaitGroup
}

// Distribution 对爬虫结果或者被动发现结果进行任务分发
func (t *Task) Distribution(crawlResult *input.CrawlResult) {
	if crawlResult != nil {
		if crawlResult.Headers == nil {
			crawlResult.Headers = make(map[string]string)
		}
		if value, ok := crawlResult.Headers["Content-Type"]; ok {
			crawlResult.ContentType = value
		}

		// 有参数，进行 xss、sql 注入检测
		if crawlResult.Kv != "" {
			if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "SQL") {
				go t.sqlInjection(crawlResult)
			}

			if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "XSS") {
				go t.xss(crawlResult)
			}

			if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "CMD-INJECT") {
				go t.cmdinject(crawlResult)
			}

			if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "XXE") {
				go t.xxe(crawlResult)
			}

			if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "SSRF") {
				go t.ssrf(crawlResult)
			}

		}

		if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "BRUTE") {
			go brute.Hydra("", 0, "")
		}

		if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "JSONP") {
			go t.jsonp(crawlResult)
		}

		if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "CRLF") {
			go t.crlf(crawlResult)
		}
	}
}

// sql 注入检测
func (t *Task) sqlInjection(crawlResult *input.CrawlResult) {
	t.wg.Add()
	sqlInjection.Scan(crawlResult)
	t.wg.Done()
}

// xss 检测
func (t *Task) xss(crawlResult *input.CrawlResult) {
	t.wg.Add()
	// todo 后续改改，这个 dalfox 发送了太多请求
	xss.Scan(crawlResult)
	t.wg.Done()
}

// jsonp 检测
func (t *Task) jsonp(crawlResult *input.CrawlResult) {
	t.wg.Add()
	jsonp.Scan(crawlResult)
	t.wg.Done()
}

// crlf 检测
func (t *Task) crlf(crawlResult *input.CrawlResult) {
	t.wg.Add()
	crlf.Scan(crawlResult)
	t.wg.Done()
}

// cmd inject 检测
func (t *Task) cmdinject(crawlResult *input.CrawlResult) {
	t.wg.Add()
	cmdinject.Scan(crawlResult)
	t.wg.Done()
}

// xxe 检测
func (t *Task) xxe(crawlResult *input.CrawlResult) {
	t.wg.Add()
	xxe.Scan(crawlResult)
	t.wg.Done()
}

// ssrf 检测
func (t *Task) ssrf(crawlResult *input.CrawlResult) {
	t.wg.Add()
	ssrf.Scan(crawlResult)
	t.wg.Done()
}
