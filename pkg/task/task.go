package task

import (
	"github.com/remeh/sizedwaitgroup"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/scan/brute"
	"github.com/yhy0/Jie/scan/cmdinject"
	"github.com/yhy0/Jie/scan/crlf"
	"github.com/yhy0/Jie/scan/jsonp"
	"github.com/yhy0/Jie/scan/sqlInjection"
	"github.com/yhy0/Jie/scan/ssrf"
	"github.com/yhy0/Jie/scan/xss"
	"github.com/yhy0/Jie/scan/xxe"
	"path"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: //TODO
**/

type Task struct {
	TaskId string
	Input  *input.Input
	//Target                *Request
	CrawlResult   *CrawlResult // 爬虫结果,主动的爬虫就不需要考虑重复问题了
	PassiveResult string       // todo 被动代理模式，需要考虑到重复数据的问题，防止重复发payload
	Parallelism   int          // 同时运行任务个数
	wg            sizedwaitgroup.SizedWaitGroup
}

//type Request struct {
//	Target       string            `json:"target"` // 目标 首页地址
//	Url          string            `json:"url"`    // 抓取到的 url
//	Ip           string            `json:"ip"`
//	Port         int               `json:"port"`
//	Service      string            `json:"service"`
//	StatusCode   int               `json:"status_code"`
//	IndexLen     int               `json:"index_len"`
//	IndexBody    string            `json:"index_body"`
//	Fingerprints []string          `json:"fingerprints"`
//	Param        string            `json:"param"`
//	Header       map[string]string `json:"header"`
//	Body         string            `json:"body"`
//	Method       string            `json:"method"`
//}

// Distribution 对爬虫结果或者被动发现结果进行任务分发
func (t *Task) Distribution() {
	t.wg = sizedwaitgroup.New(t.Parallelism)
	if t.CrawlResult != nil {
		t.Input.Url = t.CrawlResult.URL
		t.Input.Method = t.CrawlResult.Method
		t.Input.Headers = t.CrawlResult.Headers
		if value, ok := t.Input.Headers["Content-Type"]; ok {
			t.Input.ContentType = value
		}

		// 有参数，进行 xss、sql 注入检测
		if t.CrawlResult.Kv != "" {
			
			if funk.Contains(t.Input.Plugins, "SQL") {
				go t.sqlInjection()
			}

			if funk.Contains(t.Input.Plugins, "XSS") {
				go t.xss()
			}

			if funk.Contains(t.Input.Plugins, "CMD-INJECT") {
				go t.cmdinject()
			}

			if funk.Contains(t.Input.Plugins, "XXE") {
				go t.xxe()
			}

			if funk.Contains(t.Input.Plugins, "SSRF") {
				go t.ssrf()
			}

		}

		if funk.Contains(t.Input.Plugins, "POC") {
			// todo 针对性 POC 检测
			suffix := path.Ext(t.CrawlResult.File)
			if suffix == ".asp" {

			} else if suffix == ".aspx" {

			} else if suffix == ".jsp" || suffix == ".do" || suffix == ".action" {

			} else if suffix == ".php" {

			}
		}

		if funk.Contains(t.Input.Plugins, "BRUTE") {
			go brute.Hydra("", 0, "")
		}
		if funk.Contains(t.Input.Plugins, "JSONP") {
			go t.jsonp()
		}
		if funk.Contains(t.Input.Plugins, "CRLF") {
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

// cmd inject 检测
func (t *Task) cmdinject() {
	t.wg.Add()
	cmdinject.Scan(t.Input)
	t.wg.Done()
}

// xxe 检测
func (t *Task) xxe() {
	t.wg.Add()
	xxe.Scan(t.Input)
	t.wg.Done()
}

// ssrf 检测
func (t *Task) ssrf() {
	t.wg.Add()
	ssrf.Scan(t.Input)
	t.wg.Done()
}
