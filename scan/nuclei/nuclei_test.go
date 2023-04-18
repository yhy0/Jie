package nuclei

import (
	"github.com/logrusorgru/aurora"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/logging"
	"sync"
	"testing"
)

/**
  @author: yhy
  @since: 2023/1/31
  @desc: //TODO
**/

func TestNuclei(t *testing.T) {
	logging.New(false, "")
	conf.GlobalConfig = &conf.Config{}
	httpx.NewSession()
	conf.GlobalConfig.WebScan.Proxy = "http://127.0.0.1:8080"

	// 使用 sync.WaitGroup 防止 OutChannel 中的数据没有完全被消费，导致的数据漏掉问题
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for v := range output.OutChannel {
			logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
		}
	}()

	Scan("https://yarx.koalr.me/", nil)

	wg.Wait()
}
