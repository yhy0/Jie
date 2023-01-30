package xss

import (
	"fmt"
	dalfox "github.com/hahwul/dalfox/v2/lib"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/output"
	"time"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: https://github.com/hahwul/dalfox/
**/

func Scan(in *input.Input) {
	opt := dalfox.Options{
		Timeout:      10,
		Delay:        2,     // 请求限速器，单位毫秒， 代表每秒 2 次请求，防止过快导致 EOF
		Mining:       false, // 使用字典攻击查找新参数，默认为GF-Patterns=>XSS
		FindingDOM:   false, // 在DOM中查找新参数(attribute/js值)
		ProxyAddress: in.Proxy,
		Concurrence:  10,
		NoBAV:        true,
		NoGrep:       true,
		UniqParam:    in.Param, // 需要限制参数， 不然请求太多了
	}
	result, err := dalfox.NewScan(dalfox.Target{
		URL:     in.Url,
		Method:  in.Method,
		Options: opt,
	})
	if err != nil {
		logging.Logger.Errorln(err)
	} else if len(result.PoCs) > 0 {
		for _, v := range result.PoCs {
			output.OutChannel <- output.VulMessage{
				DataType: "web_vul",
				Plugin:   "XSS - " + v.InjectType,
				VulData: output.VulData{
					CreateTime: time.Now().Format("2006-01-02 15:04:05"),
					Target:     in.Url,
					Method:     in.Method,
					Ip:         "",
					Param:      "",
					Payload:    fmt.Sprintf("%s \n", v.Data),
				},
				Level: v.Severity,
			}
		}
		logging.Logger.Printf("Logs: %+v, PoCs: %+v, Params: %+v", result.Logs, result.PoCs, result.Params)
	}
}
