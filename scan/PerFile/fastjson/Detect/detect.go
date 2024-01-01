package Detect

import (
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/pkg/reverse"
    "github.com/yhy0/Jie/scan/PerFile/fastjson/Utils"
    "github.com/yhy0/logging"
    "log"
    "net/http"
    "net/http/httptrace"
    "regexp"
    "strings"
    "time"
)

/**
***    识别fastjson(主要通过报错回显的方式)
**/

func Fastjson(url string, client *httpx.Client) (bool, string) {
    logging.Logger.Debugln("[" + url + "] :" + "[+] 正在进行报错识别")
    jsonType := ErrDetectVersion(url, Utils.FS_ERR_DETECT, client)
    if jsonType == "jackson" {
        return false, Utils.NOT_FS
    }
    if jsonType != "" {
        return true, jsonType
    }
    return false, jsonType
}

/**
***    探测fastjson版本，目前包括:报错探测，DNS探测和延迟探测
**/

func Version(url string, client *httpx.Client) Utils.Result {
    var result Utils.Result
    Utils.InitResult(result)
    logging.Logger.Debugln("开始检测 " + url)
    result.Url = url
    var payloads Utils.DNSPayloads
    isFastjson, jsonType := Fastjson(url, client)

    if jsonType == "jackson" {
        result.Type = jsonType
        return result
    }

    // 出网探测
    logging.Logger.Debugln("[" + result.Url + "] :" + "[+] 正在进行出网探测")
    payload, session := Utils.NET_DETECT_FACTORY()
    record := DnslogDetect(url, payload, session, client)
    if record != "" {
        if record != Utils.NETWORK_NOT_ACCESS {
            // 出网
            logging.Logger.Debugln("[" + result.Url + "] :" + "[*] 目标可出网")
            result.Netout = true
            result.Type = "Fastjson"
            logging.Logger.Debugln("[" + result.Url + "] :" + "[+] 正在进行 AutoType状态 探测")
            result.AutoType = AutoType(url, client)
            result.Dependency = Dependency(url)
            if isFastjson && jsonType != Utils.NOT_FS && jsonType != "" {
                logging.Logger.Debugln("[" + result.Url + "] :" + "[+] Fastjson版本为 " + jsonType)
                result.Version = jsonType
                result.Payload = payload
                return result
            }
            logging.Logger.Debugln("[" + result.Url + "] :" + "[+] 正在进行版本探测")
            payloads, session = Utils.DNS_DETECT_FACTORY()
            version := DnslogDetect(url, payloads.Dns_48, session, client)
            if version == "48" {
                result.Version = Utils.FJ_UNDER_48
                result.Payload = payloads.Dns_80
                return result
            }
            version = DnslogDetect(url, payloads.Dns_68, session, client)
            if version == "68" {
                if result.AutoType {
                    result.Version = Utils.FJ_BEYOND_48
                    result.Payload = payloads.Dns_68
                    return result
                }
                result.Version = Utils.FJ_BETWEEN_48_68
                result.Payload = payloads.Dns_68
                return result
            }
            version = DnslogDetect(url, payloads.Dns_80, session, client)
            if version == "80" {
                result.Version = Utils.FJ_BETWEEN_69_80
                result.Payload = payloads.Dns_80
                return result
            }
            version = DnslogDetect(url, payloads.Dns_80, session, client)
            if version == "83" {
                result.Version = Utils.FS_BEYOND_80
                result.Payload = payloads.Dns_80
                return result
            }
            result.Payload = payloads.Dns_48 + " | " + payloads.Dns_68 + " | " + payloads.Dns_80
            result.Version = version
            return result
        } else {
            logging.Logger.Debugln("客户端与dnslog平台网络不可达")
            // 内网测试场景  施工中
        }

    } else {
        // 不出网
        logging.Logger.Debugln("[" + result.Url + "] :" + "[-] 目标不出网")
        logging.Logger.Debugln("[" + result.Url + "] :" + "[+] 正在进行延迟探测")
        if TimeDelayCheck(url) {
            result.Netout = false
            result.Type = "Fastjson"
            result.Version = Utils.FS_BETWEEN_36_62
            return result
            // fastjson > 1.2.61 且 不出网
        }
    }

    result.Type = jsonType
    return result
}

/**
*** 探测java环境依赖库
**/

func Dependency(target string) []string {
    logging.Logger.Debugln("[" + target + "] :" + "[+] 正在进行依赖库探测")
    logging.Logger.Debugln("[" + target + "] :" + "[+] 正在进行报错探测")
    var results []string
    findDependency := ErrDetectDependency(target, Utils.DEPENDENCY_ERR_DETECT_FACTORY())
    // logging.Logger.Debugln(findDependency)
    if findDependency[0] == "" {
        logging.Logger.Debugln("[" + target + "] :" + "[-] 报错探测未发现任何依赖库")
        results = make([]string, 1)
        results[0] = ""
    } else {
        logging.Logger.Debugln("[" + target + "] :" + "[*] 发现依赖库如下")
        for dependency := range findDependency {
            if findDependency[dependency] != "" {
                logging.Logger.Debugln(findDependency[dependency])
                results = append(results, findDependency[dependency])
            }

        }
    }
    return results
}

/**
*** Autotype 开启检测，需出网
*** return  True 为 开启 ; False 为 关闭
**/

func AutoType(url string, client *httpx.Client) bool {
    dnslog := reverse.GetDnslogUrl()
    if dnslog == nil {
        return false
    }
    var autoTypeStatus bool
    payload := Utils.AUTOTYPE_DETECT_FACTORY(dnslog.Domain)
    record := DnslogDetect(url, payload, dnslog.Session, client)
    if record == "" || record == Utils.NETWORK_NOT_ACCESS {
        logging.Logger.Debugln("[" + url + "] :" + "[-] 目标没有开启 AutoType")
        autoTypeStatus = false
    } else {
        logging.Logger.Debugln("[" + url + "] :" + "[*] 目标开启了 AutoType ")
        autoTypeStatus = true
    }
    return autoTypeStatus
}

func DnslogDetect(target string, payload string, session string, client *httpx.Client) string {
    header := map[string]string{
        "Content-Type": "application/json",
    }
    httpRsp, err := client.Request(target, "POST", payload, header)
    if err != nil {
        logging.Logger.Debugln("与dns平台网络不可达,请检查网络", err)
        return Utils.NETWORK_NOT_ACCESS
    }

    reg := regexp.MustCompile(`fastjson-version\s\d.\d.[0-9]+`)
    var version string
    version = reg.FindString(httpRsp.Body)
    if version != "" {
        return version[17:]
    }

    time.Sleep(3 * time.Second) // 等3秒钟，防止由于网络原因误报
    logging.Logger.Debugln(payload + ":" + reverse.GetDnslogRecord(session))

    body := reverse.GetDnslogRecord(session)
    if body == "" {
        return ""
    }
    dns_48 := regexp.MustCompile(`48_.`)
    dns_68 := regexp.MustCompile(`68_.`)
    dns_80 := regexp.MustCompile(`80_.`)
    dns_83 := regexp.MustCompile(`83_.`)

    if dns_48.FindString(body) != "" {
        return "48"
    }
    if dns_68.FindString(body) != "" {
        return "68"
    }
    if dns_83.FindString(body) != "" {
        return "83"
    }
    if dns_80.FindString(body) != "" {
        return "80"
    }
    return "Recorded"
}

/**
*** 报错探测
**/

func ErrDetectVersion(target string, payload string, client *httpx.Client) string {
    var version string
    header := map[string]string{
        "Content-Type": "application/json",
    }
    httpRsp, err := client.Request(target, "POST", payload, header)
    if err != nil {
        logging.Logger.Debugln("与dns平台网络不可达,请检查网络", err)
        return Utils.NETWORK_NOT_ACCESS
    }

    reg := regexp.MustCompile(`fastjson-version\s\d.\d.[0-9]+`)

    version = reg.FindString(httpRsp.Body)
    if version == "" {
        reg = regexp.MustCompile(`jackson`)
        version = reg.FindString(httpRsp.Body)
        return version
    } else {
        return version[17:]
    }
}

func ErrDetectDependency(target string, payloadsMap map[string]string) []string {
    var result = make([]string, len(payloadsMap))
    var cursor = 0
    for dependencyName, payload := range payloadsMap {
        header := map[string]string{
            "Content-Type": "application/json",
        }
        httpRsp, err := httpx.Request(target, "POST", payload, header)
        if err != nil {
            logging.Logger.Debugln("与dns平台网络不可达,请检查网络", err)
            continue
        }
        reg := regexp.MustCompile(dependencyName)

        find := reg.FindString(httpRsp.Body)
        if find != "" {
            result[cursor] = dependencyName
            cursor++
        }
    }
    return result
}

/**
*** 延迟探测
**/

func TimeDelayCheck(url string) bool {
    var count int
    var start int64
    var pos int64 = 0
    for i := 0; i < 6; i++ {
        start = pos
        payloads := Utils.TIME_DETECT_FACTORY(6)
        pos = TimeGet(url, payloads[i])
        if pos-start > 0 {
            count++
        }
    }
    if count > 4 {
        return true
    }
    return false
}

/**
*** 获取请求的时间
**/

func TimeGet(url string, payload string) int64 {
    reqBody := strings.NewReader(payload)
    req, _ := http.NewRequest("POST", url, reqBody)
    var start time.Time

    trace := &httptrace.ClientTrace{
        GotFirstResponseByte: func() {
            // fmt.Printf("Time from start to first byte: %v\n", time.Since(start))
        },
    }
    req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
    start = time.Now()
    if _, err := http.DefaultTransport.RoundTrip(req); err != nil {
        log.Fatal(err)
    }
    // fmt.Printf("Total time: %v\n", time.Since(start))
    return int64(time.Since(start))
}
