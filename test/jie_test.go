package test

import (
	"fmt"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"testing"
)

/**
   @author yhy
   @since 2023/8/23
   @desc //TODO
**/

func TestJie(t *testing.T) {
	conf.GlobalConfig = &conf.Config{}

	conf.GlobalConfig.Options.Proxy = ""
	//conf.GlobalConfig.WebScan.Plugins = []string{"XSS", "SQL", "CMD", "XXE", "SSRF", "POC", "BRUTE", "JSONP", "CRLF", "BBSCAN"}
	conf.GlobalConfig.WebScan.Plugins = []string{"XSS"}
	conf.GlobalConfig.WebScan.Poc = nil
	conf.GlobalConfig.Reverse.Host = ""
	conf.GlobalConfig.Reverse.Domain = ""
	conf.GlobalConfig.Debug = false

	// 初始化 session
	httpx.NewSession()

	response, err := httpx.Get("https://public-firing-range.appspot.com/dom/")
	if err != nil {
		return
	}

	fmt.Println(response.ContentLength)
	fmt.Println(response.ResponseDump)
}
