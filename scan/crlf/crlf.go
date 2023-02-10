package crlf

import (
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"regexp"
	"strings"
	"time"
)

const (
	RegexRule = `(?i)[\n|\r](Somecustominjectedheader\s*:\s*injected_by_wvs)`
)

// crlf Check
var payloadTemplate = []string{
	`/%0ASomecustominjectedheader: injected_by_wvs`,
	`\r\nSomeCustomInjectedHeader: injected_by_wvs`,
	`\r\n\tSomeCustomInjectedHeader: injected_by_wvs`,
	`\r\n SomeCustomInjectedHeader: injected_by_wvs`,
	`\r\tSomeCustomInjectedHeader: injected_by_wvs`,
	`\nSomeCustomInjectedHeader: injected_by_wvs`,
	`\rSomeCustomInjectedHeader: injected_by_wvs`,
	`\rSomeCustomInjectedHeader: injected_by_wvs`,
	`%E5%98%8A%E5%98%8DSomeCustomInjectedHeader:%20injected_by_wvs`,
	`%c4%8d%c4%8aSomeCustomInjectedHeader:%20injected_by_wvs`,
}

func Scan(in *input.CrawlResult) {
	r, _ := regexp.Compile(RegexRule)
	for _, pl := range payloadTemplate {
		if strings.ToUpper(in.Method) == "GET" {
			npl := in.Url + pl
			res, err := httpx.Request(npl, in.Method, "", false, in.Headers)

			if err != nil {
				logging.Logger.Debugf("Request error: %v", err)
				return
			}

			r, err := regexp.Compile(RegexRule)
			if err != nil {
				logging.Logger.Debugf("%s", err.Error())
				return
			}

			C := r.FindAllStringSubmatch(httpx.Header(res.Header), -1)
			if len(C) != 0 {
				output.OutChannel <- output.VulMessage{
					DataType: "web_vul",
					Plugin:   "CRLF",
					VulData: output.VulData{
						CreateTime: time.Now().Format("2006-01-02 15:04:05"),
						Target:     in.Url,
						Method:     in.Method,
						Ip:         in.Ip,
						Param:      "",
						Request:    res.RequestDump,
						Response:   res.ResponseDump,
						Payload:    npl,
					},
					Level: output.Medium,
				}
				return
			}

		} else {
			res, err := httpx.Request(in.Url, in.Method, in.Resp.Body+pl, false, in.Headers)
			if err != nil {
				logging.Logger.Debugf("Request error: %v", err)
				return
			}
			if str := r.FindString(httpx.Header(res.Header)); str != "" {
				output.OutChannel <- output.VulMessage{
					DataType: "web_vul",
					Plugin:   "CRLF",
					VulData: output.VulData{
						CreateTime: time.Now().Format("2006-01-02 15:04:05"),
						Target:     in.Url,
						Method:     in.Method,
						Ip:         in.Ip,
						Param:      "",
						Request:    res.RequestDump,
						Response:   res.ResponseDump,
						Payload:    in.Resp.Body + pl,
					},
					Level: output.Medium,
				}
				return
			}
		}
	}

}
