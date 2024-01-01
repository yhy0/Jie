package crawler

import (
    "encoding/json"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/crawler/crawlergo"
    "github.com/yhy0/Jie/crawler/crawlergo/config"
    "github.com/yhy0/Jie/crawler/crawlergo/engine"
    "github.com/yhy0/logging"
)

type Result struct {
    ReqList       []Request `json:"req_list"`
    AllReqList    []Request `json:"all_req_list"`
    AllDomainList []string  `json:"all_domain_list"`
    SubDomainList []string  `json:"sub_domain_list"`
}

type Request struct {
    Url     string                 `json:"url"`
    Method  string                 `json:"method"`
    Headers map[string]interface{} `json:"headers"`
    Data    string                 `json:"data"`
    Source  string                 `json:"source"`
}

var (
    TaskConfig crawlergo.TaskConfig
    Browser    *engine.Browser
)

func NewBrowser(noHeadless bool) {
    Browser = engine.InitBrowser("", noHeadless)
}

func NewCrawlergo(noHeadless bool) {
    TaskConfig = crawlergo.TaskConfig{
        MaxTabsCount:            8,
        MaxRunTime:              60 * 60 * 999,
        FilterMode:              "smart",
        MaxCrawlCount:           config.MaxCrawlCount,
        TabRunTimeout:           config.TabRunTimeout,
        DomContentLoadedTimeout: config.DomContentLoadedTimeout,
        EventTriggerMode:        config.EventTriggerAsync,
        EventTriggerInterval:    config.EventTriggerInterval,
        BeforeExitDelay:         config.BeforeExitDelay,
        IgnoreKeywords:          config.DefaultIgnoreKeywords,
        Proxy:                   conf.GlobalConfig.Http.Proxy,
        ExtraHeadersString:      `{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"}`,
    }
    NewBrowser(noHeadless)
}

func getJsonSerialize(result *crawlergo.Result) []byte {
    var res Result
    var reqList []Request
    for _, _req := range result.ReqList {
        var req Request
        req.Method = _req.Method
        req.Url = _req.URL.String()
        req.Source = _req.Source
        req.Data = _req.PostData
        req.Headers = _req.Headers
        reqList = append(reqList, req)
    }

    res.ReqList = reqList
    res.AllDomainList = result.AllDomainList
    res.SubDomainList = result.SubDomainList

    resBytes, err := json.Marshal(res)
    if err != nil {
        logging.Logger.Fatal("Marshal result error")
    }
    return resBytes
}
