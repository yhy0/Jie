package weblogic

import (
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/logging"
)

func CVE_2018_2894(url string) bool {
	if req, err := httpx.Request(url+"/ws_utc/begin.do", "GET", "", false, nil); err == nil {
		if req2, err2 := httpx.Request(url+"/ws_utc/config.do", "GET", "", false, nil); err2 == nil {
			if req.StatusCode == 200 || req2.StatusCode == 200 {
				logging.Logger.Infoln("[Vulnerable] CVE_2018_2894 ", url)
				return true
			}
		}
	}
	logging.Logger.Debugln("[Safety] CVE_2018_2894 ", url)
	return false
}
