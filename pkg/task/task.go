package task

import (
    "fmt"
    "github.com/remeh/sizedwaitgroup"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/fingprints"
    "github.com/yhy0/Jie/pkg/input"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/pkg/util"
    "github.com/yhy0/Jie/scan/Pocs/pocs_go"
    "github.com/yhy0/Jie/scan/gadget/collection"
    "github.com/yhy0/Jie/scan/gadget/jwt"
    "github.com/yhy0/Jie/scan/gadget/sensitive"
    scan_util "github.com/yhy0/Jie/scan/util"
    "github.com/yhy0/logging"
    "net/url"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: TODO  ~~后期看看有没有必要设计成插件式的，自我感觉没必要，还不如这样写，逻辑简单易懂~~
        最终还是插件式比较好 ，哈哈
           todo 漏洞检测逻辑有待优化, 每个插件扫描到漏洞后，需要及时退出，不再进行后续扫描, 插件内部应该设置一个通知，扫描到漏洞即停止
**/

var lock sync.Mutex

type Task struct {
    Fingerprints []string                      // 这个只有主动会使用，被动只会新建一个 task，所以不会用到
    Parallelism  int                           // 一个网站同时扫描的最大 url 个数
    Wg           sizedwaitgroup.SizedWaitGroup // 限制同时运行的任务数量
    ScanTask     map[string]*ScanTask
}

type ScanTask struct {
    PerServer map[string]bool // 判断当前目标的 web server 是否扫过  key 为插件名字
    PerFolder map[string]bool // 判断当前目标的目录是否扫过    这里的 key 为插件名_目录名 比如 bbscan_/admin
    PocPlugin map[string]bool // 用来 poc 漏洞模块对应的指纹扫描是否扫，poc 模块依托于指纹识别，只有识别到了才会扫描
    Client    *httpx.Client   // 用来进行请求的 client
    Archive   bool            // 用来判断是否扫描过
    // 限制每个扫描任务同时运行的扫描插件个数
    Wg sizedwaitgroup.SizedWaitGroup
}

var rex = regexp.MustCompile(`//#\s+sourceMappingURL=(.*\.map)`)

var seenRequests sync.Map // 这里主要是为了一些返回包检测类的判断是否识别过，减小开销，扫描类内部会判断是否扫描过

// Distribution 对爬虫结果或者被动发现结果进行任务分发
func (t *Task) Distribution(in *input.CrawlResult) {
    if !conf.NoProgressBar {
        atomic.AddInt64(&output.TaskCounter, 1)
    }
    
    t.Wg.Add()
    defer func() {
        t.Wg.Done()
        logging.Logger.Debugln("Done", in.Url)
        if !conf.NoProgressBar {
            atomic.AddInt64(&output.TaskCompletionCounter, 1)
        }
    }()
    
    logging.Logger.Debugln(fmt.Sprintf("[%s] [%s] %s 扫描任务开始", in.UniqueId, in.Method, in.Url))
    // 这些返回包内容检测、指纹识别等因为没有使用检测是否扫描的逻辑，所以会重复检测，造成一定程度的资源消耗，问题应该不大
    // TODO 还没有想好怎么写逻辑，因为一些扫描插件会用到这些结果，搞成插件化的话，就需要控制插件的执行顺序，后续看看吧，目前影响不大
    msg := output.SCopilotData{
        Target: in.Host,
    }
    
    if in.Headers == nil {
        in.Headers = make(map[string]string)
    } else {
        if value, ok := in.Headers["Content-Type"]; ok {
            in.ContentType = value
        }
    }
    
    var hostNoPort string
    port := strings.Split(in.Host, ":")
    if len(port) > 1 {
        hostNoPort = strings.Split(in.Host, ":")[0]
    } else {
        hostNoPort = in.Host
    }
    
    in.Ip = hostNoPort
    
    if t.ScanTask[in.Host] == nil {
        lock.Lock()
        t.ScanTask[in.Host] = &ScanTask{
            PerServer: make(map[string]bool),
            PerFolder: make(map[string]bool),
            PocPlugin: make(map[string]bool),
            Client:    httpx.NewClient(nil),
            // 3: 同时运行 3 个插件，3 供 PreServer、 PreFolder、PerFile这三个函数使用，防止马上退出 所以这里同时运行的插件个数为3-5 个
            // TODO 更优雅的实现方式
            Wg: sizedwaitgroup.New(3 + 3),
        }
        lock.Unlock()
    }
    
    // cdn 只检测一次
    if !t.ScanTask[in.Host].PerServer["cdnCheck"] {
        lock.Lock()
        t.ScanTask[in.Host].PerServer["cdnCheck"] = true
        lock.Unlock()
        if _, ok := output.IPInfoList[hostNoPort]; !ok {
            // cdn 检测
            matched, value, itemType, dnsData := util.CheckCdn(hostNoPort)
            var ip string
            var allRecords []string
            if dnsData != nil {
                ip = strings.Join(dnsData.A, " ")
                allRecords = dnsData.AllRecords
            }
            output.IPInfoList[hostNoPort] = &output.IPInfo{
                Ip:         ip,
                AllRecords: allRecords,
                Type:       itemType,
                Value:      value,
                Cdn:        matched,
            }
            in.Cdn = matched
        }
    }
    
    msg.HostNoPort = hostNoPort
    
    // 指纹识别, 插件扫描会用到, 还是放到这里吧，多次识别也不影响
    fingerprints := fingprints.Identify([]byte(in.Resp.Body), in.Resp.Header)
    if len(fingerprints) > 0 {
        msg.Fingerprints = append(msg.Fingerprints, fingerprints...)
        in.Fingerprints = util.RemoveDuplicateElement(append(in.Fingerprints, msg.Fingerprints...))
    }
    
    msg.SiteMap = append(msg.SiteMap, in.Url)
    
    msg.CollectionMsg = collection.Info(in.Url, hostNoPort, in.Resp.Body, in.ContentType)
    
    // 请求头中存在 Authorization 时，看看是不是 JWT ，如果是，自动对 JWT 进行爆破
    if v, ok := in.Headers["Authorization"]; ok {
        value := strings.Split(v, " ") // 有的 JWT ，是 Xxx Jwt 这种格式
        var jwtString string
        if len(value) > 1 {
            jwtString = value[1]
        } else {
            jwtString = value[0]
        }
        // 一个 jwt 解析爆破一次就好了
        if !jwt.Jwts[jwtString] {
            // 首先解析一下，看看是不是 Jwt
            _, err := jwt.ParseJWT(jwtString)
            if err == nil { // 没有报错，说明解析 Jwt 成功
                msg.Fingerprints = util.RemoveDuplicateElement(append(msg.Fingerprints, "jwt"))
                in.Fingerprints = util.RemoveDuplicateElement(append(in.Fingerprints, msg.Fingerprints...))
                jwt.Jwts[jwtString] = true
                secret := jwt.GenerateSignature()
                if secret != "" {
                    output.OutChannel <- output.VulMessage{
                        DataType: "web_vul",
                        Plugin:   "JWT",
                        VulnData: output.VulnData{
                            CreateTime: time.Now().Format("2006-01-02 15:04:05"),
                            Target:     in.Url,
                            Method:     in.Method,
                            Ip:         in.Ip,
                            Payload:    secret,
                        },
                        Level: output.Critical,
                    }
                }
            }
        }
    }
    
    // 没有检测到 shiro 时，扫描的请求中添加一个 请求头检测一下 Cookie: rememberMe=3
    // TODO 这里不对，添加到这里，返回的数据包并没有经过这里，放到 httpx.request(...) 中 进行指纹检测的话，怎么返回获取指纹？还是说对于这种指纹检测，主动进行一次发包 (不太想使用这种方式)
    if !util.InSliceCaseFold("shiro", in.Fingerprints) {
        if in.Headers["Cookie"] != "" {
            in.Headers["Cookie"] = in.Headers["Cookie"] + ";rememberMe=3"
        } else {
            in.Headers["Cookie"] = "rememberMe=3"
        }
    }
    
    // 更新数据
    output.SCopilot(in.Host, msg)
    
    sensitive.KeyDetection(in.Url, in.Resp.Body)
    
    errorMsg := sensitive.PageErrorMessageCheck(in.Url, in.RawRequest, in.Resp.Body)
    if len(errorMsg) > 0 {
        var res []string
        for _, v := range errorMsg {
            msg.Fingerprints = append(msg.Fingerprints, v.Type)
            res = append(res, v.Text)
        }
        msg.PluginMsg = []output.PluginMsg{
            {
                Url:      in.Url,
                Result:   res,
                Request:  in.RawRequest,
                Response: in.RawResponse,
            },
        }
    }
    
    // 非 css、js 类进行扫描, 单独进行 判断是否识别过
    if !strings.HasSuffix(in.ParseUrl.Path, ".css") && !strings.HasSuffix(in.ParseUrl.Path, ".js") {
        // 插件扫描
        t.Run(in)
        // poc 模块依托于指纹识别，只有识别到对应的指纹才会扫描，所以这里就不插件化了
        if conf.Plugin["poc"] {
            lock.Lock()
            t.ScanTask[in.Host].PocPlugin = pocs_go.PocCheck(in.Fingerprints, in.Target, in.Url, in.Ip, t.ScanTask[in.Host].PocPlugin, t.ScanTask[in.Host].Client)
            lock.Unlock()
        }
    } else {
        // 下面这些使用去重逻辑，因为扫描结果不会被别的插件用到
        if isScanned(in.UniqueId) {
            return
        }
        
        if strings.HasSuffix(in.ParseUrl.Path, ".js") {
            // 对于 js 这种单独判断是否扫描过，减少消耗
            if strings.HasPrefix(in.Resp.Body, "webpackJsonp(") || strings.Contains(in.Resp.Body, "window[\"webpackJsonp\"]") {
                msg.Fingerprints = util.RemoveDuplicateElement(append(msg.Fingerprints, "Webpack"))
                in.Fingerprints = util.RemoveDuplicateElement(append(in.Fingerprints, msg.Fingerprints...))
            }
            
            // 前端 js 中存在 sourcemap 文件，即 xxx.js.map 这种可以使用 sourcemap 等工具还原前端代码
            match := rex.FindStringSubmatch(in.Resp.Body)
            if match != nil {
                msg.Fingerprints = util.RemoveDuplicateElement(append(msg.Fingerprints, "SourceMap"))
                in.Fingerprints = util.RemoveDuplicateElement(append(in.Fingerprints, msg.Fingerprints...))
                
                output.OutChannel <- output.VulMessage{
                    DataType: "web_vul",
                    Plugin:   "SourceMap",
                    VulnData: output.VulnData{
                        CreateTime: time.Now().Format("2006-01-02 15:04:05"),
                        Target:     in.Url,
                    },
                    Level: output.Low,
                }
            }
        }
    }
    
    // 更新数据
    output.SCopilot(in.Host, msg)
    
    go func() {
        // 判断 Archive 是否有数据，如果有的话分发至扫描
        if !t.ScanTask[in.Host].Archive && in.Archive != nil {
            for k, v := range in.Archive {
                response, err := t.ScanTask[in.Host].Client.Request(v, "GET", "", nil)
                if err != nil {
                    continue
                }
                if response.StatusCode == 200 && !scan_util.IsBlackHtml(response.Body, response.Header["Content-Type"]) {
                    parseUrl, err := url.Parse(v)
                    if err != nil {
                        continue
                    }
                    i := &input.CrawlResult{
                        Target:   in.Target,
                        Url:      v,
                        Host:     in.Host,
                        ParseUrl: parseUrl,
                        UniqueId: k,
                        Method:   "GET",
                        Resp: &httpx.Response{
                            Status:     strconv.Itoa(response.StatusCode),
                            StatusCode: response.StatusCode,
                            Body:       response.Body,
                            Header:     response.Header,
                        },
                        RawRequest:  response.RequestDump,
                        RawResponse: response.ResponseDump,
                    }
                    t.Run(i)
                }
            }
        }
        
        t.ScanTask[in.Host].Archive = true
    }()
}

func isScanned(key string) bool {
    if key == "" {
        return false
    }
    if _, ok := seenRequests.Load(key); ok {
        return true
    }
    seenRequests.Store(key, true)
    return false
}
