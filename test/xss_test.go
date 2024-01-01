package test

import (
    "fmt"
    "github.com/logrusorgru/aurora"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/crawler"
    "github.com/yhy0/Jie/pkg/mode"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/pkg/task"
    "github.com/yhy0/Jie/scan/PerFile/xss/dom"
    "github.com/yhy0/logging"
    "sync"
    "testing"
)

/**
   @author yhy
   @since 2023/8/24
   @desc //TODO
**/

func TestDomXss(t *testing.T) {
    logging.Logger = logging.New(true, "", "Jie", true)
    // 获取扫描结果
    var l sync.Mutex
    var count = 0
    go output.GenerateVulnReport("vulnerability_report.html")
    go func() {
        for v := range output.OutChannel {
            output.ReportMessageChan <- v
            l.Lock()
            count += 1
            l.Unlock()
            logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
        }
    }()

    conf.GlobalConfig = &conf.Config{}

    conf.GlobalConfig.Http.Proxy = ""
    conf.GlobalConfig.WebScan.Poc = nil
    conf.GlobalConfig.Reverse.Host = ""
    conf.GlobalConfig.Reverse.Domain = ""
    conf.GlobalConfig.Debug = false

    // 初始化爬虫
    crawler.NewCrawlergo(true)
    task := &task.Task{
        Parallelism: conf.Parallelism,
        ScanTask:    make(map[string]*task.ScanTask),
        // Fingerprints: technologies,
    }

    mode.Crawler("https://public-firing-range.appspot.com/dom/", nil, task)
    fmt.Println(count)
}

func TestDom1Xss(t *testing.T) {
    logging.Logger = logging.New(true, "", "domxss", true)
    conf.GlobalConfig = &conf.Config{}
    // conf.GlobalConfig.Options.Proxy = "http://127.0.0.1:8080"

    // 获取扫描结果
    go func() {
        for v := range output.OutChannel {
            logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
        }
    }()

    response, err := httpx.Get("https://public-firing-range.appspot.com/dom/toxicdom/document/cookie_set/eval")
    if err != nil {
        return
    }

    dom.Dom("https://public-firing-range.appspot.com/dom/toxicdom/document/cookie_set/eval", response.Body)
}
