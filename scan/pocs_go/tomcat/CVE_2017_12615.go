package tomcat

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
)

func CVE_2017_12615(url string) bool {
	if req, err := http.Request(url+"/vtset.txt", "PUT", "test", false, nil); err == nil {
		if req.StatusCode == 204 || req.StatusCode == 201 {
			return true
		}
	}
	return false
}
