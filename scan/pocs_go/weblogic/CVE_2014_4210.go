package weblogic

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
)

func CVE_2014_4210(url string) bool {
	if req, err := http.Request(url+"/uddiexplorer/SearchPublicRegistries.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			return true
		}
	}
	return false
}
