package task

import (
	"github.com/remeh/sizedwaitgroup"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/scan/cmdinject"
	"github.com/yhy0/Jie/scan/crlf"
	"github.com/yhy0/Jie/scan/jsonp"
	"github.com/yhy0/Jie/scan/sqlmap"
	"github.com/yhy0/Jie/scan/ssrf"
	"github.com/yhy0/Jie/scan/xss"
	"github.com/yhy0/Jie/scan/xxe"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: TODO  后期看看有没有必要设计成插件式的，自我感觉没必要，还不如这样写，逻辑简单易懂
  		 todo 漏洞检测逻辑有待优化, 每个插件扫描到漏洞后，需要及时退出，不再进行后续扫描, 插件内部应该设置一个通知，扫描到漏洞即停止
**/

type Task struct {
	TaskId        string
	Target        string
	Fingerprints  []string
	PassiveResult string // todo 被动代理模式，需要考虑到重复数据的问题，防止重复发payload
	Parallelism   int    // 一个网站同时扫描的最大 url 个数
	wg            sizedwaitgroup.SizedWaitGroup
	limit         chan struct{}
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

		if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "XSS") {
			// 防止创建过多的协程
			t.limit <- struct{}{}
			go t.xss(crawlResult)
		}

		// 有参数，进行 sql 注入检测
		if crawlResult.Kv != "" {
			if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "SQL") {
				t.limit <- struct{}{}
				go t.sqlInjection(crawlResult)
			}

			if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "CMD") {
				t.limit <- struct{}{}
				go t.cmdinject(crawlResult)
			}

			if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "XXE") {
				t.limit <- struct{}{}
				go t.xxe(crawlResult)
			}

			if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "SSRF") {
				t.limit <- struct{}{}
				go t.ssrf(crawlResult)
			}

		}

		//if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "BRUTE") {
		//	t.limit <- struct{}{}
		//	go brute.Hydra("", 0, "")
		//}

		if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "JSONP") {
			t.limit <- struct{}{}
			go t.jsonp(crawlResult)
		}

		if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "CRLF") {
			t.limit <- struct{}{}
			go t.crlf(crawlResult)
		}
	}
}

// sql 注入检测
func (t *Task) sqlInjection(crawlResult *input.CrawlResult) {
	t.wg.Add()
	sqlmap.Scan(crawlResult)
	<-t.limit
	t.wg.Done()
}

// xss 检测
func (t *Task) xss(crawlResult *input.CrawlResult) {
	t.wg.Add()
	xss.Scan(crawlResult)
	<-t.limit
	t.wg.Done()
}

// jsonp 检测
func (t *Task) jsonp(crawlResult *input.CrawlResult) {
	t.wg.Add()
	jsonp.Scan(crawlResult)
	<-t.limit
	t.wg.Done()
}

// crlf 检测
func (t *Task) crlf(crawlResult *input.CrawlResult) {
	t.wg.Add()
	crlf.Scan(crawlResult)
	<-t.limit
	t.wg.Done()
}

// cmd inject 检测
func (t *Task) cmdinject(crawlResult *input.CrawlResult) {
	t.wg.Add()
	cmdinject.Scan(crawlResult)
	<-t.limit
	t.wg.Done()
}

// xxe 检测
func (t *Task) xxe(crawlResult *input.CrawlResult) {
	t.wg.Add()
	xxe.Scan(crawlResult)
	<-t.limit
	t.wg.Done()
}

// ssrf 检测
func (t *Task) ssrf(crawlResult *input.CrawlResult) {
	t.wg.Add()
	ssrf.Scan(crawlResult)
	<-t.limit
	t.wg.Done()
}
