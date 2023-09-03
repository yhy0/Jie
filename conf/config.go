package conf

import "sync"

/**
  @author: yhy
  @since: 2023/2/1
  @desc: //TODO
**/

var (
	DefaultPlugins = []string{"XSS", "SQL", "CMD", "XXE", "SSRF", "BRUTE", "JSONP", "CRLF", "BBSCAN"}
)

type Config struct {
	WebScan WebScan `json:"web_scan"`
	Passive string  `json:"passive"`
	Reverse Reverse `json:"reverse"`
	Debug   bool    `json:"debug"`
	Options Options `json:"options"`
}

type WebScan struct {
	Poc     []string `json:"poc"`
	Plugins []string `json:"plugins"`
}

type Reverse struct {
	Host   string `json:"host"`
	Domain string `json:"domain"`
}

var GlobalConfig *Config

// Visited 防止重复爬取的, 保证并发安全
var Visited = &sync.Map{}
