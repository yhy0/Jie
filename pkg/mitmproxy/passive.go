package mitmproxy

import (
    "github.com/thoas/go-funk"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/mitmproxy/go-mitmproxy/proxy"
    "github.com/yhy0/Jie/pkg/util"
    "path/filepath"
)

/**
  @author: yhy
  @since: 2023/10/10
  @desc: go-mitmproxy 插件，用来获取流量信息
**/

type PassiveAddon struct {
    proxy.BaseAddon
    done chan bool
}

// Response 对有响应的进行测试
func (pa *PassiveAddon) Response(f *proxy.Flow) {
    if f.Request.Method == "CONNECT" {
        return
    }
    // 过滤一些干扰项
    if len(conf.GlobalConfig.Mitmproxy.Exclude) > 0 || !(len(conf.GlobalConfig.Mitmproxy.Exclude) == 1 && conf.GlobalConfig.Mitmproxy.Exclude[0] == "") {
        if !util.RegexpStr(conf.GlobalConfig.Mitmproxy.Exclude, f.Request.URL.Host) {
            judge(f)
        }
    } else {
        judge(f)
    }
}

func judge(f *proxy.Flow) {
    if len(conf.GlobalConfig.Mitmproxy.Include) > 0 && !(len(conf.GlobalConfig.Mitmproxy.Include) == 1 && conf.GlobalConfig.Mitmproxy.Include[0] == "") {
        if util.RegexpStr(conf.GlobalConfig.Mitmproxy.Include, f.Request.URL.Host) {
            ext := filepath.Ext(f.Request.URL.Path)
            // 过滤一些后缀, 比如 mp4 等，但 .css .js 还是要放过的，要进行敏感信息检测
            var flag = false
            if ext != "" {
                flag = funk.Contains(conf.GlobalConfig.Mitmproxy.FilterSuffix, ext)
            }
            if !flag {
                distribution(f)
            }
        }
    } else {
        ext := filepath.Ext(f.Request.URL.Path)
        // 过滤一些后缀, 比如 mp4 等，但 .css .js 还是要放过的，要进行敏感信息检测
        var flag = false
        if ext != "" {
            flag = funk.Contains(conf.GlobalConfig.Mitmproxy.FilterSuffix, ext)
        }
        if !flag {
            distribution(f)
        }
    }
}
