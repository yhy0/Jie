package apollo

import (
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/logging"
	"testing"
)

func TestApollo(t *testing.T) {
	logging.New(true, "", "agent", true)
	conf.GlobalConfig = &conf.Config{}
	conf.GlobalConfig.Options.Proxy = "http://127.0.0.1:8080"
	// 初始化 session
	httpx.NewSession(100)
	Run("http://172.16.39.132:8091", "http://172.16.39.132:8089")
}
