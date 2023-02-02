package conf

/**
  @author: yhy
  @since: 2023/2/1
  @desc: //TODO
**/

var (
	DefaultPlugins = []string{"XSS", "SQL", "CMD-INJECT", "XXE", "SSRF", "POC", "BRUTE", "JSONP", "CRLF"}
)

type Config struct {
	WebScan WebScan `json:"web_scan"`
	Passive string  `json:"passive"`
	Reverse Reverse `json:"reverse"`
}

type WebScan struct {
	Poc     []string `json:"poc"`
	Plugins []string `json:"plugins"`
	Proxy   string   `json:"proxy"`
}

type Reverse struct {
	Domain string `json:"domain"`
	Token  string `json:"token"`
}

var GlobalConfig *Config
