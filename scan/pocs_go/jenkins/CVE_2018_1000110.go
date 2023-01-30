package jenkins

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
	"strings"
)

func CVE_2018_1000110(u string) bool {
	if req, err := http.Request(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := http.Request(u+"/search/?q=a", "GET", "", false, nil); err == nil {
				if strings.Contains(req2.Body, "Search for 'a'") {
					return true
				}
			}
		}
	}
	return false
}
