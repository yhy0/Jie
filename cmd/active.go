package cmd

import (
	"fmt"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/protocols/http"
	"github.com/yhy0/Jie/pkg/task"
	"github.com/yhy0/Jie/pkg/util"
	"github.com/yhy0/Jie/scan/nuclei"
	"github.com/yhy0/Jie/scan/waf"
	"regexp"
)

/**
  @author: yhy
  @since: 2023/1/11
  @desc: 爬虫主动扫描数据处理
**/

// Active 主动扫描 调用爬虫扫描, 只会输入一个域名
func Active(target string) {
	if target == "" {
		logging.Logger.Errorln("target must be set")
		return
	}

	// 判断是否以 http https 开头
	httpMatch, _ := regexp.MatchString("^(http)s?://", target)
	if !httpMatch {
		portMatch, _ := regexp.MatchString(":443", target)
		if portMatch {
			target = fmt.Sprintf("https://%s", target)
		} else {
			target = fmt.Sprintf("http://%s", target)
		}
	}

	// 爬虫前，进行连接性、指纹识别、 waf 探测
	resp, err := http.Request(target, "GET", "", false, nil)
	if err != nil {
		logging.Logger.Errorln(err)
		return
	}

	logging.Logger.Debugln("Start active crawler scan")
	t := task.Task{
		TaskId:      util.UUID(),
		Target:      target,
		Parallelism: 10,
	}

	wafs := waf.Scan(target, resp.Body)

	// 爬虫的同时进行指纹识别
	t.Crawler(wafs)

	logging.Logger.Debugln("Fingerprints: ", t.Fingerprints)
	// 一个网站应该只执行一次 POC 检测, poc 检测放到最后
	if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "POC") {
		// 这里根据指纹进行对应的检测
		nuclei.Scan(target, t.Fingerprints)
	}

}
