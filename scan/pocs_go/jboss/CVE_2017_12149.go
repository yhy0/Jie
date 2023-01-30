package jboss

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
)

func CVE_2017_12149(url string) bool {
	if req, err := http.Request(url+"/invoker/readonly", "GET", "", false, nil); err == nil {
		if req.StatusCode == 500 {
			return true
		}
	}
	return false
}
