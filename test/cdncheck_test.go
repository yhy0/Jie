package test

import (
    "fmt"
    "github.com/yhy0/Jie/pkg/util"
    "testing"
)

func TestCDNCheckValid(t *testing.T) {
    
    found, provider, itemType, dnsData := util.CheckCdn("173.245.48.12")
    
    fmt.Println(found)
    fmt.Println(provider)
    fmt.Println(itemType)
    if dnsData != nil {
        fmt.Println(dnsData.A)
    }
    
    fmt.Println("=================")
    found, provider, itemType, dnsData = util.CheckCdn("www.baidu.com")
    
    fmt.Println(found)
    fmt.Println(provider)
    fmt.Println(itemType)
    if dnsData != nil {
        fmt.Println(dnsData.A)
    }
}
