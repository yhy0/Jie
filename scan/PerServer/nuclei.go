package PerServer

import (
    "github.com/yhy0/Jie/pkg/input"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/scan/Pocs/nuclei"
    "sync"
)

/**
   @author yhy
   @since 2023/11/20
   @desc //TODO
**/

type NucleiPlugin struct {
    SeenRequests sync.Map
}

func (p *NucleiPlugin) Scan(target string, path string, in *input.CrawlResult, client *httpx.Client) {
    if in.Cdn {
        return
    }
    if p.IsScanned(in.UniqueId) {
        return
    }

    NucleiScan(target, in.Fingerprints)
}

func (p *NucleiPlugin) IsScanned(key string) bool {
    if key == "" {
        return false
    }
    if _, ok := p.SeenRequests.Load(key); ok {
        return true
    }
    p.SeenRequests.Store(key, true)
    return false
}

func (p *NucleiPlugin) Name() string {
    return "nuclei"
}

func NucleiScan(target string, fingerprints []string) {
    // 这里根据指纹进行对应的检测,TODO 还没搞好怎么和指纹匹配后再扫描
    nuclei.Scan(target, fingerprints)
}
