package filter

import (
    "github.com/yhy0/Jie/crawler/crawlergo/config"
    "github.com/yhy0/Jie/crawler/crawlergo/model"
    "strings"

    mapset "github.com/deckarep/golang-set/v2"
)

type SimpleFilter struct {
    UniqueSet       mapset.Set[string]
    HostLimit       string
    staticSuffixSet mapset.Set[string]
}

func NewSimpleFilter(host string) *SimpleFilter {
    staticSuffixSet := config.StaticSuffixSet.Clone()

    for _, suffix := range []string{"js", "css", "json"} {
        staticSuffixSet.Add(suffix)
    }
    s := &SimpleFilter{UniqueSet: mapset.NewSet[string](), staticSuffixSet: staticSuffixSet, HostLimit: host}
    return s
}

// DoFilter 需要过滤则返回 true
func (s *SimpleFilter) DoFilter(req *model.Request) bool {
    if s.UniqueSet == nil {
        s.UniqueSet = mapset.NewSet[string]()
    }
    // 首先判断是否需要过滤域名
    if s.HostLimit != "" && s.DomainFilter(req) {
        return true
    }
    // 去重
    if s.UniqueFilter(req) {
        return true
    }
    // 过滤静态资源
    if s.StaticFilter(req) {
        return true
    }
    return false
}

// UniqueFilter 请求去重
func (s *SimpleFilter) UniqueFilter(req *model.Request) bool {
    if s.UniqueSet == nil {
        s.UniqueSet = mapset.NewSet[string]()
    }
    if s.UniqueSet.Contains(req.UniqueId()) {
        return true
    } else {
        s.UniqueSet.Add(req.UniqueId())
        return false
    }
}

/*
*
静态资源过滤
*/
func (s *SimpleFilter) StaticFilter(req *model.Request) bool {
    if s.UniqueSet == nil {
        s.UniqueSet = mapset.NewSet[string]()
    }
    // 首先将slice转换成map

    if req.URL.FileExt() == "" {
        return false
    }
    if s.staticSuffixSet.Contains(req.URL.FileExt()) {
        return true
    }
    return false
}

/*
*
只保留指定域名的链接
*/
func (s *SimpleFilter) DomainFilter(req *model.Request) bool {
    if s.UniqueSet == nil {
        s.UniqueSet = mapset.NewSet[string]()
    }
    if req.URL.Host == s.HostLimit || req.URL.Hostname() == s.HostLimit {
        return false
    }
    if strings.HasSuffix(s.HostLimit, ":80") && req.URL.Port() == "" && req.URL.Scheme == "http" {
        if req.URL.Hostname()+":80" == s.HostLimit {
            return false
        }
    }
    if strings.HasSuffix(s.HostLimit, ":443") && req.URL.Port() == "" && req.URL.Scheme == "https" {
        if req.URL.Hostname()+":443" == s.HostLimit {
            return false
        }
    }
    return true
}
