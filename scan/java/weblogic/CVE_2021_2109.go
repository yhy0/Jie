package weblogic

import (
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/logging"
	"strings"
)

func CVE_2021_2109(url string) bool {
	if req, err := httpx.Request(url+"/console/css/%252e%252e%252f/consolejndi.portal", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "Weblogic") {
			logging.Logger.Infoln("[Vulnerable] CVE_2021_2109 ", url)
			return true
		}
	}
	logging.Logger.Debugln("[Safety] CVE_2021_2109 ", url)
	return false
}
