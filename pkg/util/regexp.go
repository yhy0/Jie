package util

import (
	"regexp"
)

/**
  @author: yhy
  @since: 2023/2/10
  @desc: //TODO
**/

func MatchAnyOfRegexp(regexps []string, match string) (bool, string) {
	for _, value := range regexps {
		regex := regexp.MustCompile(value)
		if regex.MatchString(match) {
			return true, value
		}
	}

	return false, ""
}
