package jenkins

import (
	"fmt"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/util"
)

func Unauthorized(u string) bool {
	if req, err := httpx.Request(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := httpx.Request(u+"/script", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && util.Contains(req2.Body, "Groovy script") {
					logging.Logger.Println(fmt.Sprintf("Found vuln Jenkins Unauthorized script|%s\n", u+"/script"))
					return true
				}
			}
			if req2, err := httpx.Request(u+"/computer/(master)/scripts", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && util.Contains(req2.Body, "Groovy script") {
					logging.Logger.Println(fmt.Sprintf("Found vuln Jenkins Unauthorized script|%s\n", u+"/computer/(master)/scripts"))
					return true
				}
			}
		}
	}
	return false
}
