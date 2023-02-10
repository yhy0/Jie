package weblogic

import "github.com/yhy0/Jie/pkg/protocols/httpx"

func CVE_2014_4210(url string) bool {
	if req, err := httpx.Request(url+"/uddiexplorer/SearchPublicRegistries.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			return true
		}
	}
	return false
}
