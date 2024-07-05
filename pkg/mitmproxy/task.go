package mitmproxy

import (
    "github.com/yhy0/Jie/pkg/mitmproxy/go-mitmproxy/proxy"
    "github.com/yhy0/Jie/pkg/util"
    "github.com/yhy0/logging"
    "net/url"
    "strings"
    
    "github.com/yhy0/Jie/pkg/input"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "strconv"
)

/**
  @author: yhy
  @since: 2023/10/10
  @desc: 判断是否扫描过，不能在这里进行，防止一开始某些插件没开，运行中开启导致无法扫描，判断是否扫描过的逻辑放到每个插件内部中
**/

// distribution 分发被动流量请求任务
func distribution(f *proxy.Flow) {
    parseUrl, err := url.Parse(f.Request.URL.String())
    if err != nil {
        logging.Logger.Errorln(err)
        return
    }
    
    var host string
    // 有的会带80、443端口号，导致    example.com 和 example.com:80、example.com:443被认为是不同的网站
    port := strings.Split(parseUrl.Host, ":")
    if len(port) > 1 && (port[1] == "443" || port[1] == "80") {
        host = strings.Split(parseUrl.Host, ":")[0]
    } else {
        host = parseUrl.Host
    }
    
    // 使用解码后的，不然有的 js f.Response.Body 直接乱码
    var body []byte
    body, err = f.Response.DecodedBody()
    if err != nil {
        body = f.Response.Body
    }
    
    // TODO 将 http.Header 转换为 map[string]string 有的重复请求头，这里后面遇到了再优化吧
    headerMap := make(map[string]string)
    for key, values := range f.Request.Header {
        // 根据HTTP头名称选择分隔符
        separator := ","
        if key == "Set-Cookie" {
            separator = ";"
        }
        
        // 将多个值连接成一个字符串，用逗号分隔
        headerMap[key] = strings.Join(values, separator)
    }
    
    in := &input.CrawlResult{
        Target:      f.Request.URL.Host,
        Url:         f.Request.URL.String(),
        Host:        host,
        ParseUrl:    parseUrl,
        UniqueId:    util.UniqueId(f.Request),
        Method:      f.Request.Method,
        RequestBody: string(f.Request.Body),
        Headers:     headerMap,
        Resp: &httpx.Response{
            Status:     strconv.Itoa(f.Response.StatusCode),
            StatusCode: f.Response.StatusCode,
            Body:       string(body),
            Header:     f.Response.Header,
        },
        RawRequest:  requestDump(f.Request),
        RawResponse: responseDump(f),
    }
    
    t.WG.Add(1)
    go func() {
        err = t.Pool.Submit(t.Distribution(in))
        if err != nil {
            t.WG.Done()
            logging.Logger.Errorf("add distribution err:%v, crawlResult:%v", err, in)
        }
    }()
    // t.Distribution(in)
}
