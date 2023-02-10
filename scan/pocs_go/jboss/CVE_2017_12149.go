package jboss

import "github.com/yhy0/Jie/pkg/protocols/httpx"

func CVE_2017_12149(url string) bool {
	if req, err := httpx.Request(url+"/invoker/readonly", "GET", "", false, nil); err == nil {
		if req.StatusCode == 500 {
			return true
		}
	}
	return false
}
