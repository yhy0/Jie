package test

import (
    "github.com/yhy0/Jie/SCopilot"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/mode"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/logging"
    "testing"
)

/**
  @author: yhy
  @since: 2023/10/10
  @desc: //TODO
**/

func TestPassive(t *testing.T) {
    logging.New(true, "", "Passive", true)
    conf.Init()
    conf.GlobalConfig.Debug = true
    // conf.GlobalConfig.Http.Proxy = "http://127.0.0.1:8080"
    conf.GlobalConfig.Passive.ProxyPort = ":9081"
    conf.GlobalConfig.Passive.WebPort = "9088"
    conf.GlobalConfig.Passive.WebUser = "yhy"
    // 全部插件关闭
    for k := range conf.Plugin {
        conf.Plugin[k] = true
    }

    // conf.Plugin["xss"] = false
    // conf.Plugin["sql"] = true
    // conf.Plugin["cmd"] = true
    // conf.Plugin["xxe"] = true
    // conf.Plugin["ssrf"] = true
    // conf.Plugin["jsonp"] = true

    // conf.DefaultPlugins["portScan"] = true
    // conf.GlobalConfig.SqlmapApi = conf.Sqlmap{
    //    On:       true,
    //    Url:      "http://127.0.0.1:8775",
    //    Username: "test",
    //    Password: "test",
    // }

    if conf.GlobalConfig.Passive.WebPort != "" {
        go SCopilot.Init()
    }

    // 结果输出
    go output.Write(true)

    mode.Passive()
}
