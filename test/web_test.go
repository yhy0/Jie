package test

import (
    "github.com/iancoleman/orderedmap"
    "github.com/yhy0/Jie/SCopilot"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/input"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/scan"
    "github.com/yhy0/logging"
    "net/http"
    "testing"
)

/**
   @author yhy
   @since 2024/5/13
   @desc //TODO
**/

func TestWeb(t *testing.T) {
    logging.Logger = logging.New(true, "", "web", true)
    conf.Init()
    conf.GlobalConfig.Passive.WebPort = "9088"
    conf.GlobalConfig.Passive.WebUser = "yhy"
    conf.GlobalConfig.Passive.WebPass = "123"
    paras := orderedmap.New()
    
    paramNames := []string{"id", "url", "cunt", "appid", "id", "appid", "id", "op", "token"}
    for _, _para := range paramNames {
        v, ok := paras.Get(_para)
        if ok {
            paras.Set(_para, v.(int)+1)
        } else {
            paras.Set(_para, 1)
        }
    }
    
    // 按照value的字典序升序排序
    paras.Sort(func(a *orderedmap.Pair, b *orderedmap.Pair) bool {
        return a.Value().(int) > b.Value().(int)
    })
    
    msg := output.SCopilotData{
        Target:     "example.com",
        Ip:         "192.168.0.1",
        HostNoPort: "example.com",
        SiteMap: []string{
            "https://example.com/",
            "https://example.com/about",
            "https://example.com/contact",
            "https://example.com/about/1",
            "https://example.com/about/2",
            "https://example.com/about/1?id=1",
        },
        Fingerprints: []string{
            "Apache/2.4.29 (Ubuntu)",
            "PHP/7.2.24",
        },
        VulMessage: []output.VulMessage{
            {
                DataType: "vuln",
                VulnData: output.VulnData{
                    CreateTime:  "2022-01-01 10:00:00",
                    VulnType:    "SQL Injection",
                    Target:      "example.com",
                    Ip:          "192.168.0.1",
                    Method:      "POST",
                    Param:       "id",
                    Payload:     "1' OR '1'='1",
                    CURLCommand: "curl -X POST -d 'id=1' OR '1'='1' http://example.com",
                    Description: "This is a SQL Injection vulnerability.",
                    Request:     "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 7\n\nid=1",
                    Header:      "HTTP/1.1 200 OK\nContent-Type: text/html\n\n",
                    Response:    "<html><body>Invalid credentials</body></html>",
                },
                Plugin: "SQL Injection Scanner",
                Level:  output.High,
            },
        },
        VulPlugin: map[string]int{
            "SQL Injection Scanner": 1,
        },
        InfoMsg: []output.PluginMsg{
            {
                Url:      "http://example.com/about",
                Plugin:   "Information Disclosure Scanner",
                Result:   []string{"Sensitive information exposed."},
                Request:  "GET /about HTTP/1.1\nHost: example.com\n\n",
                Response: "<html><body>About page content</body></html>",
            },
        },
        InfoPlugin: map[string]int{
            "Information Disclosure Scanner": 1,
        },
        PluginMsg: []output.PluginMsg{
            {
                Url:      "http://example.com/contact",
                Plugin:   "Contact Form Vulnerability Scanner",
                Result:   []string{"Contact form is vulnerable to XSS."},
                Request:  "POST /contact HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 20\n\nmessage=<script>alert('XSS')</script>",
                Response: "<html><body>Thank you for your message.</body></html>",
            },
        },
        CollectionMsg: output.Collection{
            Subdomain:   []string{"sub1.example.com", "sub2.example.com"},
            OtherDomain: []string{"example.net", "example.org"},
            PublicIp:    []string{"203.0.113.1", "203.0.113.2"},
            InnerIp:     []string{"192.168.0.2", "192.168.0.3"},
            Phone:       []string{"1234567890", "0987654321"},
            Email:       []string{"test@example.com", "info@example.com"},
            IdCard:      []string{"123456789012345678", "987654321098765432"},
            Others:      []string{"data1", "data2"},
            Api:         []string{"/api/v1/book", "/api/v1/", "/api/v2/2", "/api/v1/2/", "/api/v1/book/1"},
            Urls:        []string{"http://api.example.com", "https://api.example.com"},
            Parameters:  paras,
        },
    }
    header := make(http.Header)
    header["Content-Type"] = []string{"application/json"}
    in := &input.CrawlResult{
        Url:        "http://example.com/login?token=admin",
        Method:     "POST",
        ParamNames: paramNames,
        RawRequest: "POST /login?token=admin HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 7\n\nid=1",
        Resp: &httpx.Response{
            Header: header,
            Body:   "{\"id\": 1,\"key\":\"test\"}",
        },
        RawResponse: "{\"id\": 1,\"key\":\"test\"}",
    }
    // 结果输出
    go output.Write(true)
    
    scan.PerFilePlugins["SensitiveParameters"].Scan("", "", in, nil)
    
    output.SCopilot("example.com", msg)
    SCopilot.Init()
}
