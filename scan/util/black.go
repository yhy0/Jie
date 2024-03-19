package util

import (
    regexp "github.com/wasilibs/go-re2"
    "github.com/yhy0/Jie/pkg/util"
    "strings"
)

/**
   @author yhy
   @since 2023/8/24
   @desc //TODO
**/

// BlackLists 命中的页面直接丢弃
var BlackLists []BlackRule

// BlackRule bbscan 黑名单
type BlackRule struct {
    Type string
    Rule string
}

func IsBlackHtml(str string, contentType []string) bool {
    for _, rule := range BlackLists {
        if rule.Type == "text" {
            if util.Contains(str, rule.Rule) {
                return true
            }
        } else if rule.Type == "regexText" {
            reg, _ := regexp.Compile(rule.Rule)
            if len(reg.FindStringSubmatch(str)) > 0 {
                return true
            }
        } else {
            if strings.ToLower(str) == strings.ToLower(rule.Rule) {
                return true
            }
        }
    }
    
    if len(str) < 250 && util.InSliceCaseFold("application/json", contentType) {
        reg, _ := regexp.Compile(`(?i)("(status|code|statusCode)"(\s+)?:(\s+)?(400|401|404|502)|"(message|msg)"(\s+)?:(\s+)?.*?(not exist|not found|请求非法)|not found)`)
        if len(reg.FindStringSubmatch(str)) > 0 {
            return true
        }
    }
    
    return false
}
