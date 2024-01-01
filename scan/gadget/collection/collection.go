package collection

import (
    "github.com/BishopFox/jsluice"
    "github.com/thoas/go-funk"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/Jie/pkg/util"
    "github.com/yhy0/logging"
    "golang.org/x/net/publicsuffix"
    "net"
    "net/url"
    "regexp"
    "strings"
)

/**
  @author: yhy
  @since: 2023/11/1
  @desc: //TODO
**/

// Info  domain: 用来限制获取的子域名
func Info(target, domain string, body string, contentType string) (c output.Collection) {
    logging.Logger.Debugln("start collection url:", target)
    var domains []string
    for _, v := range conf.GlobalConfig.Collection.Domain {
        re := regexp.MustCompile(v)
        domains = util.RemoveQuotation(re.FindAllString(body, -1))
    }

    // 使用 publicsuffix 包获取二级域名
    _domain, _ := publicsuffix.EffectiveTLDPlusOne(domain)
    for _, d := range domains {
        // 正则会匹配到 .com.cn 这种，需要过滤掉 . 开头的
        if strings.HasPrefix(d, ".") {
            continue
        }
        d = strings.ReplaceAll(d, "http://", "")
        d = strings.ReplaceAll(d, "https://", "")
        d = strings.ReplaceAll(d, "://", "")
        d = strings.ReplaceAll(d, "//", "")
        if strings.Contains(d, _domain) {
            c.Subdomain = append(c.Subdomain, d)
        } else {
            c.OtherDomain = append(c.OtherDomain, d)
        }
    }

    var ips []string
    for _, v := range conf.GlobalConfig.Collection.IP {
        re := regexp.MustCompile(v)
        ips = util.RemoveQuotation(re.FindAllString(body, -1))
    }
    for _, i := range ips {
        // 正则会匹配到 .com.cn 这种，需要过滤掉 . 开头的
        if strings.HasPrefix(i, ".") {
            continue
        }
        i = strings.ReplaceAll(i, "http://", "")
        i = strings.ReplaceAll(i, "https://", "")
        i = strings.ReplaceAll(i, "://", "")
        i = strings.ReplaceAll(i, "//", "")
        // 不带端口号的，需要验证一下是否为 ip ，目前正则会匹配到 1.2.840.100 这种
        if !strings.Contains(i, ":") && net.ParseIP(i) == nil {
            continue
        }
        if util.IsInnerIP(i) {
            c.InnerIp = append(c.InnerIp, i)
        } else {
            c.PublicIp = append(c.PublicIp, i)
        }
    }
    for _, v := range conf.GlobalConfig.Collection.Phone {
        re := regexp.MustCompile(v)
        c.Phone = append(c.Phone, util.RemoveQuotation(re.FindAllString(body, -1))...)
    }

    for _, v := range conf.GlobalConfig.Collection.Email {
        re := regexp.MustCompile(v)
        c.Email = append(c.Email, util.RemoveQuotation(re.FindAllString(body, -1))...)
    }

    for _, v := range conf.GlobalConfig.Collection.IDCard {
        re := regexp.MustCompile(v)
        c.IdCard = append(c.IdCard, util.RemoveQuotation(re.FindAllString(body, -1))...)
    }

    for _, v := range conf.GlobalConfig.Collection.Other {
        re := regexp.MustCompile(v)
        c.Others = append(c.Others, util.RemoveQuotation(re.FindAllString(body, -1))...)
    }

    for _, v := range conf.GlobalConfig.Collection.API {
        re := regexp.MustCompile(v)
        apis := re.FindAllStringSubmatch(body, -1)
        for _, u := range apis {
            if len(u) < 3 {
                _u := util.RemoveQuotationMarks(u[0])
                // "(?:\"|')(/[^/\"']+){2,}(?:\"|')"
                if _u == "" || !strings.HasPrefix(_u, "/") {
                    continue
                }
                c.Api = append(c.Api, _u)
            } else {
                // "(?i)\\.(get|post|put|delete|options|connect|trace|patch)\\([\"'](/?.*?)[\"']" 这个正则
                // 不是以 / 开头的去除
                if u[2] == "" || !strings.HasPrefix(u[2], "/") {
                    continue
                }
                c.Api = append(c.Api, u[1]+" "+u[2])
            }
            logging.Logger.Debugln(target, u)
        }
    }

    for _, v := range conf.GlobalConfig.Collection.UrlFilter {
        re := regexp.MustCompile(v)
        urls := re.FindAllStringSubmatch(body, -1)
        urls = urlFilter(urls)
        // 循环提取url放到结果中
        for _, u := range urls {
            if u[0] == "" {
                continue
            }
            c.Urls = append(c.Urls, u[0])
        }
    }

    if funk.Contains(contentType, "application/javascript") {
        analyzer := jsluice.NewAnalyzer([]byte(body))

        for _, res := range analyzer.GetURLs() {
            logging.Logger.Debugln("[jsluice]", target, res.URL)
            c.Api = append(c.Api, res.URL)
        }
    }

    return
}

func urlFilter(str [][]string) [][]string {
    // 对不需要的数据过滤
    for i := range str {
        if strings.Contains(str[i][0], "YYYY/") && strings.Contains(str[i][0], "MM") {
            continue
        }
        if len(str[i]) > 1 {
            str[i][0], _ = url.QueryUnescape(str[i][1])
        }
        str[i][0] = strings.TrimSpace(str[i][0])
        str[i][0] = strings.Replace(str[i][0], " ", "", -1)
        str[i][0] = strings.Replace(str[i][0], "\\/", "/", -1)
        str[i][0] = strings.Replace(str[i][0], "%3A", ":", -1)
        str[i][0] = strings.Replace(str[i][0], "%2F", "/", -1)
        // 去除不存在字符串和数字的url,判断为错误数据
        match, _ := regexp.MatchString("[a-zA-Z]+|[0-9]+", str[i][0])
        if !match {
            str[i][0] = ""
            continue
        }

        // 对抓到的域名做处理
        re := regexp.MustCompile("([a-z0-9\\-]+\\.)+([a-z0-9\\-]+\\.[a-z0-9\\-]+)(:[0-9]+)?").FindAllString(str[i][0], 1)
        if len(re) != 0 && !strings.HasPrefix(str[i][0], "http") && !strings.HasPrefix(str[i][0], "/") {
            str[i][0] = "http://" + str[i][0]
        }

        // 过滤配置的黑名单
        for i2 := range conf.GlobalConfig.Collection.UrlFilter {
            _re := regexp.MustCompile(conf.GlobalConfig.Collection.UrlFilter[i2])
            is := _re.MatchString(str[i][0])
            if is {
                str[i][0] = ""
                break
            }
        }

    }
    return str
}
