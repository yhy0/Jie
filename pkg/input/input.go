package input

import (
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/reverse"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: //TODO
**/

// Atom 用于判断是否已经运行过
var Atom = make(map[string]bool)

var ChannelInput = make(chan *Input)

// Input 扫描数据统一输入格式
type Input struct {
	Plugins               []string
	Poc                   []string
	Target                string // 输入的域名 eg: https://127.0.0.1/
	Url                   string // 这里是抓取到的 url, eg: https://127.0.0.1/login?user=admin&password=admin
	Ip                    string
	Method                string
	Proxy                 string
	Headers               map[string]string
	ContentType           string
	Body                  string
	Param                 []string         // 参数名  user,password
	Kv                    string           // 参数名和参数值  user=admin&password=admin
	IsSensorServerEnabled bool             // 是否开启传感器服务
	Reverse               *reverse.Reverse // dnslog
}

// CrawlResult 如果是被动代理模式的结果，需要考虑到重复数据的问题，防止重复发payload
type CrawlResult struct {
	Target                string            `json:"target"` // 目标 eg: https://github.com
	Url                   string            `json:"url"`
	Ip                    string            `json:"ip"`
	Port                  int               `json:"port"`
	Method                string            `json:"method"`
	Headers               map[string]string `json:"headers"`
	RequestBody           string            `json:"request_body"`
	ContentType           string            `json:"content_type"`
	Source                string            `json:"source"` // 来源
	Path                  string            `json:"path"`
	File                  string            `json:"file"`
	Hostname              string            `json:"hostname"` // 当前域名
	Rdn                   string            `json:"rdn"`      // 顶级域名
	RUrl                  string            `json:"r_url"`    // https://github.com
	Dir                   string            `json:"dir"`      // 目录
	Kv                    string            `json:"kv"`       // 参数名和参数值  user=admin&password=admin
	Param                 []string          `json:"param"`    // 参数名  user,password
	IsSensorServerEnabled bool              // 是否开启传感器服务
	Waf                   []string          `json:"waf"` // 是否存在 waf
	Resp                  *httpx.Response   `json:"resp"`
}

//
//func Input() {
//	ch := make(chan bool, 30)
//
//	for v := range ChannelInput {
//		ch <- true
//		go v.Run(ch)
//	}
//}
//
//func (input *Request) Run(ch chan bool) {
//	// poc、弱口令爆破等漏洞，只运行一次检查。 todo InputMap 每天定时清空
//	if _, ok := Atom[input.Target]; !ok {
//		logging.Logger.Infoln("start ", input)
//		Atom[input.Target] = true
//		if input.Port != 0 { // 后续考虑要不要对端口进行开放检查
//			brute.Hydra(input.Ip, input.Port, input.Service)
//		}
//
//		// todo ，二级目录要不要传进去，进行目录扫描
//		dirScan.BBscan(input.Target, input.Ip, input.StatusCode, input.IndexLen, input.IndexBody)
//
//		pocs_go.PocCheck(input.Technologies, input.Target, input.Target, input.Ip)
//	} else { // 进行一些常规检查，存在参数的进行 sql 注入、xss 等检测
//
//		if input.Param != "" {
//			sqlConfig := gosqlmap.ReqConf{
//				Url:     input.Url,
//				Headers: input.Header,
//				Data:    input.Param,
//				Method:  input.Method,
//			}
//
//			go sqlInjection.Scan(&sqlConfig, input.Ip)
//
//			// todo xss
//			go xss.Scan()
//
//		}
//	}
//
//	<-ch
//}
