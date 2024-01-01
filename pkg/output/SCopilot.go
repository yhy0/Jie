package output

import (
    "github.com/thoas/go-funk"
    "net/url"
    "sort"
    "strings"
    "sync"
)

/**
   @author yhy
   @since 2023/10/14
   @desc //TODO
**/

var SCopilotLists []*SCopilotList

var lock sync.Mutex

var SCopilotMessage = make(map[string]*SCopilotData)
var IPInfoList = make(map[string]*IPInfo)
var DataUpdated = make(chan struct{})

// SCopilot 将数据存储到 SCopilotMessage 中
func SCopilot(host string, data SCopilotData) {
    lock.Lock()
    defer lock.Unlock()
    // 判断 map 中是否存在，存在的话就 append，不存在的话就创建
    if _, ok := SCopilotMessage[host]; ok {
        // 合并去重
        SCopilotMessage[host].SiteMap = funk.UniqString(append(SCopilotMessage[host].SiteMap, data.SiteMap...))
        // 对 sitemap 链接进行排序
        sort.SliceStable(SCopilotMessage[host].SiteMap, func(i, j int) bool {
            return compareLinks(SCopilotMessage[host].SiteMap[i], SCopilotMessage[host].SiteMap[j])
        })

        SCopilotMessage[host].Fingerprints = funk.UniqString(append(SCopilotMessage[host].Fingerprints, data.Fingerprints...))

        for _, v := range data.VulMessage {
            if funk.Contains(SCopilotMessage[host].VulMessage, v) {
                continue
            }
            SCopilotMessage[host].VulMessage = append(SCopilotMessage[host].VulMessage, v)
        }

        for _, v := range data.InfoMsg {
            if funk.Contains(SCopilotMessage[host].InfoMsg, v) {
                continue
            }
            SCopilotMessage[host].InfoMsg = append(SCopilotMessage[host].InfoMsg, v)
        }

        for _, v := range data.PluginMsg {
            if funk.Contains(SCopilotMessage[host].PluginMsg, v) {
                continue
            }
            SCopilotMessage[host].PluginMsg = append(SCopilotMessage[host].PluginMsg, v)
        }

        for _, v := range SCopilotLists {
            if v.Host == host {
                v.InfoCount = len(SCopilotMessage[host].InfoMsg)
                v.ApiCount = len(SCopilotMessage[host].SiteMap)
                v.VulnCount = len(SCopilotMessage[host].VulMessage)
            }
        }

        SCopilotMessage[host].CollectionMsg.Subdomain = funk.UniqString(append(SCopilotMessage[host].CollectionMsg.Subdomain, data.CollectionMsg.Subdomain...))
        SCopilotMessage[host].CollectionMsg.OtherDomain = funk.UniqString(append(SCopilotMessage[host].CollectionMsg.OtherDomain, data.CollectionMsg.OtherDomain...))
        SCopilotMessage[host].CollectionMsg.PublicIp = funk.UniqString(append(SCopilotMessage[host].CollectionMsg.PublicIp, data.CollectionMsg.PublicIp...))
        SCopilotMessage[host].CollectionMsg.InnerIp = funk.UniqString(append(SCopilotMessage[host].CollectionMsg.InnerIp, data.CollectionMsg.InnerIp...))
        SCopilotMessage[host].CollectionMsg.Phone = funk.UniqString(append(SCopilotMessage[host].CollectionMsg.Phone, data.CollectionMsg.Phone...))
        SCopilotMessage[host].CollectionMsg.Email = funk.UniqString(append(SCopilotMessage[host].CollectionMsg.Email, data.CollectionMsg.Email...))
        SCopilotMessage[host].CollectionMsg.Others = funk.UniqString(append(SCopilotMessage[host].CollectionMsg.Others, data.CollectionMsg.Others...))
        SCopilotMessage[host].CollectionMsg.Urls = funk.UniqString(append(SCopilotMessage[host].CollectionMsg.Urls, data.CollectionMsg.Urls...))
        SCopilotMessage[host].CollectionMsg.Api = funk.UniqString(append(SCopilotMessage[host].CollectionMsg.Api, data.CollectionMsg.Api...))

    } else {
        SCopilotMessage[host] = &data
        SCopilotLists = append(SCopilotLists, &SCopilotList{
            Host: host,
        })
    }

    // 通知数据已更新 这样防止没有启动前端界面时，造成阻塞
    select {
    case DataUpdated <- struct{}{}:
    default:
    }
}

// 按照目录结构对链接进行排序的比较函数
func compareLinks(a, b string) bool {
    aURL, err := url.Parse(a)
    if err != nil {
        return false
    }
    bURL, err := url.Parse(b)
    if err != nil {
        return false
    }
    aPathComponents := strings.Split(aURL.Path, "/")
    bPathComponents := strings.Split(bURL.Path, "/")

    for i := 0; i < len(aPathComponents) && i < len(bPathComponents); i++ {
        if aPathComponents[i] != bPathComponents[i] {
            return aPathComponents[i] < bPathComponents[i]
        }
    }

    return len(aPathComponents) < len(bPathComponents)
}
