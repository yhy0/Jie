package wappalyzergo

import (
    _ "embed"
    "encoding/json"
    "strings"
)

/**
  @author: yhy
  @since: 2023/2/6
  @desc: https://github.com/0x727/FingerprintHub/
    指纹库是从上面的项目中获取的，感谢作者
**/

//go:embed web_fingerprint_v3.json
var fingerprintHub []byte

// 自定义的 FingerprintHub 不更改原文件，这样随时从原库里直接复制使用
//
//go:embed web_fingerprint.json
var fingerprint []byte

type FingerprintHub struct {
    Name           string            `json:"name"`
    Path           string            `json:"path"`
    RequestMethod  string            `json:"request_method"`
    RequestHeaders map[string]string `json:"request_headers"`
    RequestData    string            `json:"request_data"`
    StatusCode     int               `json:"status_code"`
    Headers        map[string]string `json:"headers"`
    Keyword        []string          `json:"keyword"`
    FaviconHash    []string          `json:"favicon_hash"`
    Priority       int               `json:"priority"`
}

// LoadFingerprintHubFingers 指纹初始化
func (s *Wappalyze) LoadFingerprintHubFingers() error {
    var fpSlice []FingerprintHub
    if err := json.Unmarshal(fingerprintHub, &fpSlice); err != nil {
        return err
    }

    // 加载自定义的
    var fp []FingerprintHub
    if err := json.Unmarshal(fingerprint, &fp); err != nil {
        return err
    }

    fpSlice = append(fpSlice, fp...)

    s.FingerprintHubMap = make(map[string][]FingerprintHub, len(fpSlice))

    for _, v := range fpSlice { // 聚合 path
        // 将 header 头全部转为小写，防止 写的不规范导致无法匹配
        lowercaseMap := make(map[string]string)
        for key, value := range v.Headers {
            lowercaseKey := strings.ToLower(key)
            lowercaseValue := strings.ToLower(value)
            lowercaseMap[lowercaseKey] = lowercaseValue
        }
        v.Headers = lowercaseMap

        s.FingerprintHubMap[v.Path] = append(s.FingerprintHubMap[v.Path], v)
    }

    return nil
}

func (s *Wappalyze) Identify(headers map[string][]string, body []byte) string {
    for _, v := range s.FingerprintHubMap {
        for _, fingerPrint := range v {
            if matching(headers, body, fingerPrint) {
                return fingerPrint.Name
            }
        }
    }
    return ""
}

func matching(headers map[string][]string, body []byte, f FingerprintHub) bool {
    // 将 header 头全部转为小写，防止 写的不规范导致无法匹配
    lowercaseMap := make(map[string]string)
    for key, value := range headers {
        lowercaseKey := strings.ToLower(key)
        lowercaseValue := strings.ToLower(strings.Join(value, ""))
        lowercaseMap[lowercaseKey] = lowercaseValue
    }

    flag := false
    hflag := true
    if len(f.Headers) > 0 {
        hflag = false
        for k, v := range f.Headers {
            if len(lowercaseMap[k]) <= 0 {
                hflag = false
                break
            }

            if !strings.Contains(lowercaseMap[k], v) {
                hflag = false
                break
            }
            hflag = true
        }
    }
    if len(f.Headers) > 0 && hflag {
        flag = true
    }

    // 多个关键字同时匹配
    kflag := false
    if len(f.Keyword) > 0 {
        for _, k := range f.Keyword {
            if !strings.Contains(string(body), k) {
                kflag = false
                break
            }
            kflag = true
        }
    }

    // 如果 header 和 keyword 同时存在，则同时匹配
    if len(f.Keyword) > 0 && kflag {
        flag = true
    }

    if flag {
        return true
    }

    return false
}
