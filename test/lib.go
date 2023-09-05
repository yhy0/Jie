package test

import (
	"github.com/logrusorgru/aurora"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/crawler"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/task"
	"github.com/yhy0/logging"
)

/**
  @author: yhy
  @since: 2023/3/16
  @desc: 作为第三方库引用
**/

func lib() {
	logging.New(true, "", "Jie", true)
	// 获取扫描结果
	go func() {
		for v := range output.OutChannel {
			logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
		}
	}()

	conf.GlobalConfig = &conf.Config{}

	conf.GlobalConfig.Options.Proxy = ""
	//conf.GlobalConfig.WebScan.Plugins = []string{"XSS", "SQL", "CMD", "XXE", "SSRF", "POC", "BRUTE", "JSONP", "CRLF", "BBSCAN"}
	conf.GlobalConfig.WebScan.Plugins = []string{}
	conf.GlobalConfig.WebScan.Poc = nil
	conf.GlobalConfig.Reverse.Host = ""
	conf.GlobalConfig.Reverse.Domain = ""
	conf.GlobalConfig.Debug = false

	// 初始化 session
	httpx.NewSession()

	Listen := ""
	if Listen != "" {
		// 被动扫描
		task.Passive()
	} else {
		// 初始化爬虫
		crawler.NewCrawlergo(true)
		task.Active("https://public-firing-range.appspot.com/dom/toxicdom/localStorage/function/eval")
	}

}
