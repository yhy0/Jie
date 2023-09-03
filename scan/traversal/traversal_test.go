package traversal

import (
	"github.com/logrusorgru/aurora"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/logging"
	"testing"
)

/**
   @author yhy
   @since 2023/8/15
   @desc //TODO
**/

func TestTraversal(t *testing.T) {
	logging.New(true, "", "agent", false)
	conf.GlobalConfig = &conf.Config{}
	conf.GlobalConfig.Options.Proxy = "http://127.0.0.1:8080"
	// 初始化 session
	httpx.NewSession(100)
	// 获取扫描结果
	go func() {
		for v := range output.OutChannel {
			logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
		}
	}()

	NginxAlias("http://127.0.0.1:8081/", "", nil)
}
