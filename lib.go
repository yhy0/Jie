package main

import (
    "github.com/logrusorgru/aurora"
    "github.com/yhy0/Jie/SCopilot"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/crawler"
    "github.com/yhy0/Jie/pkg/mode"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/logging"
    "net/url"
)

/**
  @author: yhy
  @since: 2023/12/28
  @desc: //TODO
**/

func lib() {
    logging.Logger = logging.New(conf.GlobalConfig.Debug, "", "Jie", true)
    conf.Init()
    conf.GlobalConfig.Http.Proxy = ""
    conf.GlobalConfig.WebScan.Craw = "k"
    conf.GlobalConfig.WebScan.Poc = nil
    conf.GlobalConfig.Reverse.Host = "https://dig.pm/"
    conf.GlobalConfig.Passive.WebPort = "9088"
    conf.GlobalConfig.Passive.WebUser = "yhy"
    conf.GlobalConfig.Passive.WebPass = "123456" // 注意修改为强口令
    
    conf.Preparations()
    
    // 全部插件开启
    for k := range conf.Plugin {
        // if k == "nuclei" || k == "poc" {
        //     continue
        // }
        conf.Plugin[k] = true
    }
    
    if conf.GlobalConfig.Passive.WebPort != "" {
        go SCopilot.Init()
    }
    
    // 初始化爬虫
    crawler.NewCrawlergo(false)
    
    go func() {
        for v := range output.OutChannel {
            // SCopilot 显示
            if conf.GlobalConfig.Passive.WebPort != "" {
                parse, err := url.Parse(v.VulnData.Target)
                if err != nil {
                    logging.Logger.Errorln(err)
                    continue
                }
                msg := output.SCopilotData{
                    Target: v.VulnData.Target,
                }
                
                if v.Level == "Low" {
                    msg.InfoMsg = []output.PluginMsg{
                        {
                            Url:      v.VulnData.Target,
                            Plugin:   v.Plugin,
                            Result:   []string{v.VulnData.Payload},
                            Request:  v.VulnData.Request,
                            Response: v.VulnData.Response,
                        },
                    }
                } else {
                    msg.VulMessage = append(msg.VulMessage, v)
                }
                output.SCopilot(parse.Host, msg)
                logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
            }
            logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
        }
    }()
    
    mode.Active("http://testphp.vulnweb.com/", nil)
}
