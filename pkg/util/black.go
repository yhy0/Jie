package util

import (
	"github.com/yhy0/Jie/conf"
	"regexp"
)

/**
   @author yhy
   @since 2023/8/24
   @desc //TODO
**/

func IsBlackHtml(str string) bool {
	for _, rule := range conf.BlackLists {
		if rule.Type == "text" {
			if Contains(str, rule.Rule) {
				return true
			}
		} else if rule.Type == "regexText" {
			reg, _ := regexp.Compile(rule.Rule)
			if len(reg.FindStringSubmatch(str)) > 0 {
				return true
			}
		}
	}
	return false
}
