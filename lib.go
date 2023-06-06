package main

import (
	"github.com/logrusorgru/aurora"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/headless"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/task"
	"github.com/yhy0/logging"
	"os"
	"os/signal"
	"syscall"
)

/**
  @author: yhy
  @since: 2023/3/16
  @desc: 作为第三方库引用
**/

func main() {

	logging.New(true, "", "Jie")
	// 获取扫描结果
	go func() {
		for v := range output.OutChannel {
			logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
		}
	}()

	conf.GlobalConfig = &conf.Config{}

	conf.GlobalConfig.WebScan.Proxy = ""
	conf.GlobalConfig.WebScan.Plugins = []string{"XSS", "SQL", "CMD", "XXE", "SSRF", "POC", "BRUTE", "JSONP", "CRLF", "BBSCAN"}
	conf.GlobalConfig.WebScan.Poc = nil
	conf.GlobalConfig.Reverse.Host = ""
	conf.GlobalConfig.Reverse.Domain = ""

	// 初始化 session
	httpx.NewSession()

	// 初始化 rod
	if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "XSS") {
		headless.Rod()
	}

	Listen := ""
	if Listen != "" {
		// 被动扫描
		task.Passive()
	} else {
		// show 是否显示无头浏览器界面
		task.Active("http://testphp.vulnweb.com/", false)
	}

	cc := make(chan os.Signal)
	// 监听信号
	signal.Notify(cc, syscall.SIGINT)
	go func() {
		for s := range cc {
			switch s {
			case syscall.SIGINT:
				if headless.RodHeadless != nil {
					headless.RodHeadless.Close()
				}
			default:
			}
		}
	}()

	if headless.RodHeadless != nil {
		headless.RodHeadless.Close()
	}

}
