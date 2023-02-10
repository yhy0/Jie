package nuclei

import (
	"github.com/logrusorgru/aurora"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/output"
	"testing"
)

/**
  @author: yhy
  @since: 2023/1/31
  @desc: //TODO
**/

func TestNuclei(t *testing.T) {
	logging.New(false)
	conf.GlobalConfig = &conf.Config{}
	httpx.NewSession()
	conf.GlobalConfig.WebScan.Proxy = "http://127.0.0.1:8080"
	go func() {
		for v := range output.OutChannel {
			logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
		}
	}()

	Scan("https://yarx.koalr.me/", nil)
}
