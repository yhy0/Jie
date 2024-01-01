package bypass403

import (
    "embed"
    "fmt"
    "github.com/yhy0/Jie/pkg/input"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/pkg/util"
    "github.com/yhy0/logging"
    "net/url"
    "strings"
    "sync"
    "time"
    "unicode"
)

/**
    @author: yhy
    @since: 2023/5/6
    @desc: bypass 403     https://github.com/devploit/dontgo403
    todo 应该考虑一下带参数的，现在不能处理带参数的，直接拼接了，不好
**/

//go:embed dict
var bypass403 embed.FS

var Dict map[string][]string

func init() {
    Dict = make(map[string][]string)
    // 返回[]fs.DirEntry
    entries, _ := bypass403.ReadDir("dict")

    for _, entry := range entries {
        content, err := bypass403.ReadFile("dict/" + entry.Name())
        if err != nil {
            continue
        }
        Dict[entry.Name()] = util.CvtLines(string(content))
    }
}

type Result struct {
    Url      string `json:"url"`
    Method   string `json:"method"`
    Request  string `json:"request"`
    Response string `json:"response"`
}

type Plugin struct {
    SeenRequests sync.Map
}

func (p *Plugin) Scan(target string, path string, in *input.CrawlResult, client *httpx.Client) {
    if in.Resp.StatusCode != 403 {
        return
    }

    if p.IsScanned(in.UniqueId) {
        return
    }

    Bypass403(in.Url, in.Method, client)
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
    return "bypass403"
}

func Bypass403(uri, m string, client *httpx.Client) {
    if !strings.HasSuffix(uri, "/") {
        uri += "/"
    }

    if m == "" {
        m = "GET"
    } else {
        m = strings.ToUpper(m)
    }

    result := method(uri, m, client)
    if result != nil {
        output.OutChannel <- output.VulMessage{
            DataType: "web_vul",
            Plugin:   "403 bypass",
            VulnData: output.VulnData{
                CreateTime: time.Now().Format("2006-01-02 15:04:05"),
                Target:     result.Url,
                Method:     result.Method,
                Request:    result.Request,
                Response:   result.Response,
            },
            Level: output.Medium,
        }
        return
    }

    result = headers(uri, m, client)
    if result != nil {
        output.OutChannel <- output.VulMessage{
            DataType: "web_vul",
            Plugin:   "403 bypass",
            VulnData: output.VulnData{
                CreateTime: time.Now().Format("2006-01-02 15:04:05"),
                Target:     result.Url,
                Method:     result.Method,
                Request:    result.Request,
                Response:   result.Response,
            },
            Level: output.Medium,
        }
        return
    }

    result = endPaths(uri, m, client)
    if result != nil {
        output.OutChannel <- output.VulMessage{
            DataType: "web_vul",
            Plugin:   "403 bypass",
            VulnData: output.VulnData{
                CreateTime: time.Now().Format("2006-01-02 15:04:05"),
                Target:     result.Url,
                Method:     result.Method,
                Request:    result.Request,
                Response:   result.Response,
            },
            Level: output.Medium,
        }
        return
    }

    result = midPaths(uri, m, client)
    if result != nil {
        output.OutChannel <- output.VulMessage{
            DataType: "web_vul",
            Plugin:   "403 bypass",
            VulnData: output.VulnData{
                CreateTime: time.Now().Format("2006-01-02 15:04:05"),
                Target:     result.Url,
                Method:     result.Method,
                Request:    result.Request,
                Response:   result.Response,
            },
            Level: output.Medium,
        }
        return
    }

    result = capital(uri, m, client)
    if result != nil {
        output.OutChannel <- output.VulMessage{
            DataType: "web_vul",
            Plugin:   "403 bypass",
            VulnData: output.VulnData{
                CreateTime: time.Now().Format("2006-01-02 15:04:05"),
                Target:     result.Url,
                Method:     result.Method,
                Request:    result.Request,
                Response:   result.Response,
            },
            Level: output.Medium,
        }
        return
    }

    result = http10(uri, m)
    if result != nil {
        output.OutChannel <- output.VulMessage{
            DataType: "web_vul",
            Plugin:   "403 bypass",
            VulnData: output.VulnData{
                CreateTime: time.Now().Format("2006-01-02 15:04:05"),
                Target:     result.Url,
                Method:     result.Method,
                Request:    result.Request,
                Response:   result.Response,
            },
            Level: output.Medium,
        }
        return
    }

    return
}

// method 通过更改请求方法，尝试绕过 403
func method(uri, m string, client *httpx.Client) *Result {
    ch := make(chan struct{}, 5)
    result := &Result{}
    var flag = false
    for _, line := range Dict["httpmethods.txt"] {
        if m == line {
            continue
        }
        if flag {
            break
        }
        ch <- struct{}{}
        go func(line string) {
            resp, err := client.Request(uri, line, "", nil)
            if err != nil {
                <-ch
                return
            }
            <-ch
            if resp != nil && resp.StatusCode == 200 {
                // 遇到很多这个，测试也没发现有什么东西 应该就是这类的直接放过了
                if len(resp.Body) == 0 || resp.Header.Get("Content-Length") == "0" || strings.Contains(resp.Body, "<title>403 Forbidden</title>") || strings.Contains(resp.Body, "a padding to disable MSIE and Chrome friendly error page") {
                    return
                }
                flag = true
                result = &Result{
                    Url:      uri,
                    Method:   line,
                    Request:  resp.RequestDump,
                    Response: resp.ResponseDump,
                }
                return
            }
        }(line)
    }
    close(ch)
    if flag {
        return result
    }
    return nil
}

// headers 通过添加header，尝试绕过 403
func headers(uri, m string, client *httpx.Client) *Result {
    ch := make(chan struct{}, 10)
    result := &Result{}
    var flag = false

    for _, ip := range Dict["ips.txt"] {
        for _, line := range Dict["headers.txt"] {
            if flag {
                break
            }
            ch <- struct{}{}
            go func(ip, line string) {
                header := make(map[string]string)
                header[line] = ip
                resp, err := client.Request(uri, m, "", header)
                if err != nil {
                    <-ch
                    return
                }
                <-ch
                if resp != nil && resp.StatusCode == 200 {
                    flag = true
                    result = &Result{
                        Url:      uri,
                        Method:   m,
                        Request:  resp.RequestDump,
                        Response: resp.ResponseDump,
                    }
                    return
                }
            }(ip, line)
        }

    }

    if flag {
        return result
    }

    for _, line := range Dict["simpleheaders.txt"] {
        if flag {
            break
        }
        ch <- struct{}{}
        go func(line string) {
            x := strings.Split(line, " ")
            header := make(map[string]string)
            header[x[0]] = x[1]
            resp, err := client.Request(uri, m, "", header)
            if err != nil {
                <-ch
                return
            }
            <-ch
            if resp != nil && resp.StatusCode == 200 {
                flag = true
                result = &Result{
                    Url:      uri,
                    Method:   m,
                    Request:  resp.RequestDump,
                    Response: resp.ResponseDump,
                }
                return
            }
        }(line)
    }

    if flag {
        return result
    }
    close(ch)
    return nil
}

// endPaths 通过添加 path 后缀，尝试绕过 403
func endPaths(uri, m string, client *httpx.Client) *Result {
    ch := make(chan struct{}, 5)
    result := &Result{}
    var flag = false
    for _, line := range Dict["endpaths.txt"] {
        if flag {
            break
        }
        ch <- struct{}{}
        go func(line string) {
            resp, err := client.Request(uri+line, m, "", nil)
            if err != nil {
                <-ch
                return
            }
            <-ch
            if resp != nil && resp.StatusCode == 200 {
                flag = true
                result = &Result{
                    Url:      uri + line,
                    Method:   m,
                    Request:  resp.RequestDump,
                    Response: resp.ResponseDump,
                }
                return
            }
        }(line)
    }
    close(ch)
    if flag {
        return result
    }
    return nil
}

// midPaths 在 path 路径中间添加字符，尝试绕过 403
func midPaths(uri, m string, client *httpx.Client) *Result {
    ch := make(chan struct{}, 5)
    result := &Result{}
    var flag = false

    x := strings.Split(uri, "/")
    var uripath string

    if uri[len(uri)-1:] == "/" {
        uripath = x[len(x)-2]
    } else {
        uripath = x[len(x)-1]
    }

    baseuri := strings.ReplaceAll(uri, uripath, "")
    baseuri = baseuri[:len(baseuri)-1]

    for _, line := range Dict["midpaths.txt"] {
        if flag {
            break
        }
        ch <- struct{}{}
        go func(line string) {
            var fullpath string
            if uri[len(uri)-1:] == "/" {
                fullpath = baseuri + line + uripath + "/"
            } else {
                fullpath = baseuri + "/" + line + uripath
            }

            resp, err := client.Request(fullpath, m, "", nil)
            if err != nil {
                <-ch
                return
            }
            <-ch
            if resp != nil && resp.StatusCode == 200 {
                flag = true
                result = &Result{
                    Url:      fullpath,
                    Method:   m,
                    Request:  resp.RequestDump,
                    Response: resp.ResponseDump,
                }
                return
            }
        }(line)
    }
    close(ch)
    if flag {
        return result
    }
    return nil
}

// capital 通过将URI最后部分中的每个字母大写, 尝试绕过 403
func capital(uri, m string, client *httpx.Client) *Result {
    ch := make(chan struct{}, 5)
    result := &Result{}
    var flag = false
    x := strings.Split(uri, "/")
    var uripath string

    if uri[len(uri)-1:] == "/" {
        uripath = x[len(x)-2]
    } else {
        uripath = x[len(x)-1]
    }
    baseuri := strings.ReplaceAll(uri, uripath, "")
    baseuri = baseuri[:len(baseuri)-1]

    for _, z := range uripath {
        if flag {
            break
        }
        ch <- struct{}{}
        go func(z rune) {
            newpath := strings.Map(func(r rune) rune {
                if r == z {
                    return unicode.ToUpper(r)
                } else {
                    return r
                }
            }, uripath)

            var fullpath string
            if uri[len(uri)-1:] == "/" {
                fullpath = baseuri + newpath + "/"
            } else {
                fullpath = baseuri + "/" + newpath
            }

            resp, err := client.Request(fullpath, m, "", nil)
            if err != nil {
                <-ch
                return
            }
            <-ch
            if resp != nil && resp.StatusCode == 200 {
                flag = true
                result = &Result{
                    Url:      fullpath,
                    Method:   m,
                    Request:  resp.RequestDump,
                    Response: resp.ResponseDump,
                }
                return
            }
        }(z)
    }
    close(ch)
    if flag {
        return result
    }
    return nil
}

func http10(uri, m string) *Result {
    u, err := url.Parse(uri)
    if err != nil {
        logging.Logger.Errorln("Error url.Parse:", err)
        return nil
    }
    // 设置请求行和请求头
    raw := fmt.Sprintf("GET %s HTTP/1.0\r\n"+
        "\r\n"+
        "\r\n", u.Path+"?"+u.RawQuery)

    resp, err := httpx.Request10(u.Host, raw)
    if err != nil {
        logging.Logger.Errorln(err)
        return nil
    }
    if resp != nil && resp.StatusCode == 200 {
        return &Result{
            Url:      uri,
            Method:   "GET",
            Request:  resp.RequestDump,
            Response: resp.ResponseDump,
        }
    }

    return nil
}
