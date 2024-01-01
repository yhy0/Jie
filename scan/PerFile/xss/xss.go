package xss

import (
    "github.com/yhy0/Jie/pkg/input"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "sync"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: 语义分析、原型链污染、dom 污染点传播分析
**/

type Plugin struct {
    SeenRequests sync.Map
}

func (p *Plugin) Scan(target string, path string, in *input.CrawlResult, client *httpx.Client) {
    if p.IsScanned(in.UniqueId) {
        return
    }
    Audit(in, client)
    // dom 随主动爬虫检测了，默认就会检测
    // 原型链污染查找 xss
    // Prototype(in.Url)
}

func (p *Plugin) IsScanned(key string) bool {
    if key == "" {
        return false
    }
    if _, ok := p.SeenRequests.Load(key); ok {
        return true
    }
    p.SeenRequests.Store(key, true)
    return false
}

func (p *Plugin) Name() string {
    return "xss"
}
