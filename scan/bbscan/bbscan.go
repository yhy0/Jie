package bbscan

import (
    "github.com/antlabs/strsim"
    regexp "github.com/wasilibs/go-re2"
    "github.com/yhy0/Jie/pkg/input"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/pkg/util"
    "github.com/yhy0/Jie/scan/gadget/swagger"
    scan_util "github.com/yhy0/Jie/scan/util"
    "github.com/yhy0/logging"
    "net/url"
    "strconv"
    "strings"
    "sync"
    "time"
)

/**
    @author: yhy
    @since: 2022/9/17
    @desc: //TODO
**/

var (
    RegTag           *regexp.Regexp
    RegStatus        *regexp.Regexp
    RegContentType   *regexp.Regexp
    RegContentTypeNo *regexp.Regexp
    RegFingprints    *regexp.Regexp
    
    BlackText      *regexp.Regexp
    BlackRegexText *regexp.Regexp
    BlackAllText   *regexp.Regexp
)

type Rule struct {
    Tag        string   // 文本内容
    Status     string   // 状态码
    Type       string   // 返回的 ContentType
    TypeNo     string   // 不可能返回的 ContentType
    Fingprints []string // 指纹，只有匹配到该指纹，才会进行目录扫描
    Root       bool     // 是否为一级目录
}

var Rules map[string]*Rule

type Page struct {
    isBackUpPage bool
    title        string
    locationUrl  string
}

var (
    path404 = "/file_not_support"
)

func init() {
    Rules = make(map[string]*Rule)
    RegTag, _ = regexp.Compile(`{tag="(.*?)"}`)
    RegStatus, _ = regexp.Compile(`{status=(\d{3})}`)
    RegContentType, _ = regexp.Compile(`{type="(.*?)"}`)
    RegContentTypeNo, _ = regexp.Compile(`{type_no="(.*?)"}`)
    RegFingprints, _ = regexp.Compile(`{fingprints="(.*?)"}`)
    
    BlackText, _ = regexp.Compile(`{text="(.*)"}`)
    BlackRegexText, _ = regexp.Compile(`{regex_text="(.*)"}`)
    BlackAllText, _ = regexp.Compile(`{all_text="(.*)"}`)
    
    // 返回[]fs.DirEntry
    entries, err := rulesFiles.ReadDir("rules")
    if err != nil {
        panic(err)
    }
    for _, entry := range entries {
        rulesContent, err := rulesFiles.ReadFile("rules/" + entry.Name())
        if err != nil {
            logging.Logger.Errorf("BBscan error , read %s error: %v", entry.Name(), err)
            continue
        }
        
        if entry.Name() == "black.list" {
            for _, str := range util.CvtLines(string(rulesContent)) {
                if strings.HasPrefix(str, "#") {
                    continue
                }
                if !strings.HasPrefix(str, "{") {
                    continue
                }
                var black scan_util.BlackRule
                
                text := BlackText.FindStringSubmatch(str)
                if len(text) > 0 {
                    black.Type = "text"
                    black.Rule = text[1]
                    scan_util.BlackLists = append(scan_util.BlackLists, black)
                } else {
                    regexText := BlackRegexText.FindStringSubmatch(str)
                    if len(regexText) > 0 {
                        black.Type = "regexText"
                        black.Rule = regexText[1]
                        scan_util.BlackLists = append(scan_util.BlackLists, black)
                    } else {
                        allText := BlackAllText.FindStringSubmatch(str)
                        black.Type = "allText"
                        black.Rule = allText[1]
                        scan_util.BlackLists = append(scan_util.BlackLists, black)
                    }
                }
            }
        } else {
            for _, str := range util.CvtLines(string(rulesContent)) {
                if strings.Index(str, "/") != 0 {
                    continue
                }
                var rule Rule
                
                tag := RegTag.FindStringSubmatch(str)
                status := RegStatus.FindStringSubmatch(str)
                contentType := RegContentType.FindStringSubmatch(str)
                contentTypeNo := RegContentTypeNo.FindStringSubmatch(str)
                fingprints := RegFingprints.FindStringSubmatch(str)
                
                if len(tag) > 0 {
                    rule.Tag = tag[1]
                }
                
                if len(status) > 0 {
                    rule.Status = status[1]
                }
                if len(contentType) > 0 {
                    rule.Type = contentType[1]
                }
                if len(contentTypeNo) > 0 {
                    rule.TypeNo = contentTypeNo[1]
                }
                if len(fingprints) > 0 {
                    rule.Fingprints = strings.Split(fingprints[1], ",")
                }
                
                if util.Contains(str, "{root_only}") {
                    rule.Root = true
                }
                path := util.Trim(strings.Split(str, " ")[0])
                Rules[path] = &rule
            }
        }
    }
}

func getTitle(body string) string {
    titleReg := regexp.MustCompile(`<title>([\s\S]{1,200})</title>`)
    title := titleReg.FindStringSubmatch(body)
    if len(title) > 1 {
        return title[1]
    }
    return ""
}

func ReqPage(u string, header map[string]string, client *httpx.Client) (*Page, *httpx.Response, error) {
    page := &Page{}
    var backUpSuffixList = []string{".tar", ".tar.gz", ".zip", ".rar", ".7z", ".bz2", ".gz", ".war"}
    var method = "GET"
    
    for _, ext := range backUpSuffixList {
        if strings.HasSuffix(u, ext) {
            method = "HEAD"
        }
    }
    
    res, err := client.Request(u, method, "", header)
    if err != nil {
        return nil, nil, err
    }
    
    page.title = getTitle(res.Body)
    page.locationUrl = res.Location
    if res.StatusCode != 302 && res.Location == "" {
        regs := []string{"application/.*download", "application/.*file", "application/.*zip", "application/.*rar", "application/.*tar", "application/.*down", "application/.*compressed", "application/.*stream"}
        for _, reg := range regs {
            matched, _ := regexp.Match(reg, []byte(res.Header.Get("Content-Type")))
            if matched {
                page.isBackUpPage = true
                break
            }
        }
    }
    return page, res, err
}

// BBscan u: 目标 root: 扫描路径是否为主目录
func BBscan(u string, root bool, fingprints []string, header map[string]string, client *httpx.Client) []string {
    if strings.HasSuffix(u, "/") {
        u = u[:len(u)-1]
    }
    
    var (
        technologies []string
        resContents  []string // 找到的页面返回集合，用来进行网页相似度比较，用来去除大量的返回一样的
    )
    
    _, url404res, err := ReqPage(u+path404, header, client)
    if err == nil {
        if url404res.StatusCode == 404 {
            technologies = addFingerprints404(technologies, url404res, client) // 基于404页面文件扫描指纹添加
        }
        resContents = append(resContents, strings.ReplaceAll(url404res.Body, path404, ""))
    }
    
    wg := sync.WaitGroup{}
    ch := make(chan struct{}, 20)
    var l sync.Mutex
    count := 0
    
    for path, rule := range Rules {
        // 状态码 500 以上 30 次就不扫描了
        if count > 30 {
            return technologies
        }
        
        f := false
        // 当传入的指纹为空时，则全部规则都进行扫描
        if len(rule.Fingprints) > 0 {
            if len(fingprints) > 0 {
                // 指纹可能效果并不是很好，所以如果指纹中没有这些的话，那就全部扫描，TODO 后期指纹模块优化的很好的话，这里可以去除
                if !util.InSliceCaseFold("php", fingprints) && !util.InSliceCaseFold("java", fingprints) && !util.InSliceCaseFold("spring", fingprints) {
                    f = true
                    break
                }
                
                for _, fp := range fingprints {
                    if util.InSliceCaseFold(fp, fingprints) {
                        f = true
                        break
                    }
                }
            }
        } else {
            f = true
        }
        
        // 有指纹，但没有匹配则该规则不扫描
        if !f {
            continue
        }
        
        if util.Contains(path, "{sub}") {
            t, err := url.Parse(u)
            if err != nil {
                logging.Logger.Errorln(err)
                continue
            }
            path = strings.ReplaceAll(path, "{sub}", t.Hostname())
        }
        path = strings.TrimLeft(path, "/")
        
        // 根据传入的路径进行拼接扫描目录
        var target string
        if rule.Root { // 该路径规则只会出现在主目录下, 并且 传入的是主目录，则加上，否则不进行该规则的扫描
            if root {
                target = u + "/" + path
            } else {
                continue
            }
        } else {
            target = u + "/" + path
        }
        
        wg.Add(1)
        ch <- struct{}{}
        
        go func(t string, r *Rule) {
            defer wg.Done()
            defer func() { <-ch }()
            <-time.After(time.Duration(100) * time.Millisecond)
            page, res, err := ReqPage(t, header, client)
            
            if err == nil && res != nil {
                if res.StatusCode >= 500 {
                    l.Lock()
                    count += 1
                    l.Unlock()
                    return
                }
                
                // 黑名单，跳过
                if scan_util.IsBlackHtml(res.Body, res.Header["Content-Type"]) {
                    return
                }
                
                // ContentLength 为 0 的，都丢弃
                if res.ContentLength == 0 {
                    return
                }
                
                contentType := res.Header.Get("Content-Type")
                // 返回是个图片
                if util.Contains(contentType, "image/") {
                    return
                }
                
                if strings.HasSuffix(t, ".xml") {
                    if !util.Contains(contentType, "xml") {
                        return
                    }
                } else if strings.HasSuffix(t, ".json") {
                    if !util.Contains(contentType, "json") {
                        return
                    }
                }
                
                // 规则匹配
                if !page.isBackUpPage {
                    if len(strings.TrimSpace(res.Body)) == 0 {
                        return
                    }
                    if (r.Type != "" && !util.Contains(contentType, r.Type)) || (r.TypeNo != "" && util.Contains(contentType, r.TypeNo)) {
                        return
                    }
                    if r.Status != "" && strconv.Itoa(res.StatusCode) != r.Status {
                        return
                    }
                } else {
                    // 压缩包的单独搞，规则不太对
                    if res.StatusCode < 200 || res.StatusCode > 300 || res.ContentLength < 10 {
                        return
                    }
                    
                    // 太小的丢弃，有的 waf 会根据请求构造压缩包
                    if res.ContentLength < 100 {
                        return
                    }
                    
                }
                
                if r.Tag != "" && !util.Contains(res.Body, r.Tag) {
                    return
                }
                
                similar := false
                if len(res.Body) != 0 {
                    // 与成功的进行相似度比较，排除一些重复项 比如一个目标返回很多这种，写入黑名单的话，会有很多，所以先这样去除 {"code":99999,"msg":"未知错误","status":0}
                    for _, body := range resContents {
                        similar = strsim.Compare(body, res.Body) > 0.9 // 不相似才会往下执行
                    }
                }
                
                if !similar {
                    // 对扫到的 swagger 进行自动化测试
                    if strings.Contains(t, "swagger") {
                        swagger.Scan(t, client)
                    }
                    if res.StatusCode == 401 {
                        l.Lock()
                        technologies = append(technologies, "Basic")
                        l.Unlock()
                    }
                    
                    l.Lock()
                    technologies = append(addFingerprintsnormal(t, technologies, res, client)) // 基于200页面文件扫描指纹添加
                    resContents = append(resContents, strings.ReplaceAll(res.Body, t, ""))
                    l.Unlock()
                    
                    output.OutChannel <- output.VulMessage{
                        DataType: "web_vul",
                        Plugin:   "BBscan",
                        VulnData: output.VulnData{
                            CreateTime: time.Now().Format("2006-01-02 15:04:05"),
                            Target:     u,
                            Payload:    t,
                            Method:     "GET",
                            Request:    res.RequestDump,
                            Response:   res.ResponseDump,
                        },
                        Level: output.Low,
                    }
                }
            }
        }(target, rule)
        
    }
    
    wg.Wait()
    return technologies
}

func SingleScan(targets []string, path string) {
    rule := Rules[path]
    
    wg := sync.WaitGroup{}
    ch := make(chan struct{}, 50)
    for _, target := range targets {
        if util.Contains(path, "{sub}") {
            t, _ := url.Parse(target)
            path = strings.ReplaceAll(path, "{sub}", t.Hostname())
        }
        
        wg.Add(1)
        ch <- struct{}{}
        go func(u string) {
            defer wg.Done()
            defer func() { <-ch }()
            res, err := httpx.Request(u+path, "GET", "", nil)
            
            if err != nil {
                return
            }
            // 黑名单，跳过
            if scan_util.IsBlackHtml(res.Body, res.Header["Content-Type"]) {
                return
            }
            
            contentType := res.Header.Get("Content-Type")
            // 返回是个图片
            if util.Contains(contentType, "image/") {
                return
            }
            
            if strings.HasSuffix(path, ".xml") {
                if !util.Contains(contentType, "xml") {
                    return
                }
            } else if strings.HasSuffix(path, ".json") {
                if !util.Contains(contentType, "json") {
                    return
                }
            }
            
            // 返回包是个下载文件，但文件内容为空丢弃
            // if res.Header.Get("Content-Type") == "application/octet-stream" && res.ContentLength == 0 {
            //    return
            // }
            
            // 规则匹配
            if (rule.Type != "" && !util.Contains(contentType, rule.Type)) || (rule.TypeNo != "" && util.Contains(contentType, rule.TypeNo)) {
                return
            }
            if rule.Status != "" && strconv.Itoa(res.StatusCode) != rule.Status {
                return
            }
            
            if rule.Tag != "" && !util.Contains(res.Body, rule.Tag) {
                return
            }
            // swagger 自动化测试
            if strings.Contains(path, "swagger") {
                swagger.Scan(u+path, httpx.NewClient(nil))
            }
            
            output.OutChannel <- output.VulMessage{
                DataType: "web_vul",
                Plugin:   "BBscan",
                VulnData: output.VulnData{
                    CreateTime: time.Now().Format("2006-01-02 15:04:05"),
                    Target:     u,
                    Ip:         "",
                    Payload:    u + path,
                    Method:     "GET",
                    Request:    res.RequestDump,
                    Response:   res.ResponseDump,
                },
                Level: output.Low,
            }
        }(target)
    }
    wg.Wait()
}

type Plugin struct {
    SeenRequests sync.Map
}

func (p *Plugin) Scan(target, path string, in *input.CrawlResult, client *httpx.Client) {
    technologies := BBscan(target, path == "/", in.Fingerprints, in.Headers, client)
    in.Fingerprints = util.RemoveDuplicateElement(append(in.Fingerprints, technologies...))
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
    return "bbscan"
}
