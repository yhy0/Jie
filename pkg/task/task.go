package task

import (
	"github.com/remeh/sizedwaitgroup"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/scan/brute"
	"github.com/yhy0/Jie/scan/crlf"
	"github.com/yhy0/Jie/scan/jsonp"
	"github.com/yhy0/Jie/scan/sqlInjection"
	"github.com/yhy0/Jie/scan/xss"
	"path"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: //TODO
**/

type Task struct {
	TaskId        string
	Input         *input.Input
	Target        *Request
	CrawlResult   *CrawlResult // 爬虫结果,主动的爬虫就不需要考虑重复问题了
	PassiveResult string       // todo 被动代理，需要考虑到重复数据的问题
	Parallelism   int          // 同时运行任务个数
	wg            sizedwaitgroup.SizedWaitGroup
}

type Request struct {
	Target       string            `json:"target"` // 目标 首页地址
	Url          string            `json:"url"`    // 抓取到的 url
	Ip           string            `json:"ip"`
	Port         int               `json:"port"`
	Service      string            `json:"service"`
	StatusCode   int               `json:"status_code"`
	IndexLen     int               `json:"index_len"`
	IndexBody    string            `json:"index_body"`
	Fingerprints []string          `json:"fingerprints"`
	Param        string            `json:"param"`
	Header       map[string]string `json:"header"`
	Body         string            `json:"body"`
	Method       string            `json:"method"`
}

// Distribution 对爬虫结果或者被动发现结果进行任务分发
func (t *Task) Distribution() {
	t.wg = sizedwaitgroup.New(t.Parallelism)

	if t.CrawlResult != nil {
		t.Input.Url = t.CrawlResult.URL
		t.Input.Method = t.CrawlResult.Method
		t.Input.Headers = t.CrawlResult.Headers

		// 有参数，进行 xss、sql 注入检测
		if t.CrawlResult.Kv != "" {

			if _, ok := t.Input.Plugins["SQL"]; ok {
				go t.sqlInjection()
			}
			if _, ok := t.Input.Plugins["XSS"]; ok {
				go t.xss()
			}
		}

		if _, ok := t.Input.Plugins["POC"]; ok {
			// todo 针对性 POC 检测
			suffix := path.Ext(t.CrawlResult.File)
			if suffix == ".asp" {

			} else if suffix == ".aspx" {

			} else if suffix == ".jsp" || suffix == ".do" || suffix == ".action" {

			} else if suffix == ".php" {

			}
		}

		if _, ok := t.Input.Plugins["BRUTE"]; ok {
			go brute.Hydra("", 0, "")
		}

		if _, ok := t.Input.Plugins["JSONP"]; ok {
			go t.jsonp()
		}

		if _, ok := t.Input.Plugins["CRLF"]; ok {
			go t.crlf()
		}

	}

	t.wg.Wait()

}

// sql 注入检测
func (t *Task) sqlInjection() {
	t.wg.Add()

	sqlInjection.Scan(t.Input)

	t.wg.Done()
}

// xss 检测
func (t *Task) xss() {
	t.wg.Add()
	// todo 后续改改，这个 dalfox 发送了太多请求
	xss.Scan(t.Input)
	t.wg.Done()
}

// jsonp 检测
func (t *Task) jsonp() {
	t.wg.Add()
	jsonp.Scan(t.Input)
	t.wg.Done()
}

// crlf 检测
func (t *Task) crlf() {
	t.wg.Add()
	crlf.Scan(t.Input)
	t.wg.Done()
}
