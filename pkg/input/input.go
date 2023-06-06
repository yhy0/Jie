package input

import (
	"github.com/yhy0/Jie/pkg/protocols/httpx"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: //TODO
**/

// Atom 用于判断是否已经运行过
var Atom = make(map[string]bool)

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
