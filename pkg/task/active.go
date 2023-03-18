package task

import (
	"fmt"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/util"
	"github.com/yhy0/Jie/scan/bbscan"
	"github.com/yhy0/Jie/scan/nuclei"
	"github.com/yhy0/Jie/scan/waf"
	"github.com/yhy0/logging"
	"regexp"
	"sync"
)

/**
  @author: yhy
  @since: 2023/1/11
  @desc: 爬虫主动扫描数据处理
**/

// Active 主动扫描 调用爬虫扫描, 只会输入一个域名
func Active(target string, show bool) {
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
	resp, err := httpx.Request(target, "GET", "", false, nil)
	if err != nil {
		logging.Logger.Errorln("End: ", err)
		return
	}

	logging.Logger.Infoln("Start active crawler scan")

	var technologies []string

	if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "BBSCAN") {
		// bbscan 进行敏感目录扫描
		var mu sync.Mutex
		go func() {
			mu.Lock()
			defer mu.Unlock()
			technologies = bbscan.BBscan(target, "", resp.StatusCode, resp.ContentLength, resp.Body)
		}()
	}

	t := Task{
		TaskId:      util.UUID(),
		Target:      target,
		Parallelism: 10,
		//Fingerprints: technologies,
	}

	wafs := waf.Scan(target, resp.Body)

	// 爬虫的同时进行指纹识别
	t.Crawler(wafs, show)

	logging.Logger.Debugln("Fingerprints: ", t.Fingerprints)
	// 一个网站应该只执行一次 POC 检测, poc 检测放到最后
	if funk.Contains(conf.GlobalConfig.WebScan.Plugins, "POC") {
		t.Fingerprints = funk.UniqString(append(t.Fingerprints, technologies...))

		// 这里根据指纹进行对应的检测
		nuclei.Scan(target, t.Fingerprints)
	}

}
