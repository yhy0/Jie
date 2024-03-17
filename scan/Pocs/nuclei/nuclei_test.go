package nuclei

import (
    "fmt"
    "github.com/logrusorgru/aurora"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/logging"
    "testing"
    "time"
)

/**
  @author: yhy
  @since: 2023/1/31
  @desc: //TODO
**/

func TestNuclei(t *testing.T) {
    logging.Logger = logging.New(false, "", "1", true)
    conf.GlobalConfig = &conf.Config{}
    
    conf.GlobalConfig.Http.Proxy = "http://127.0.0.1:8080"
    // conf.GlobalConfig.WebScan.Poc = []string{"/Users/yhy/Desktop/test.yaml"}
    
    go func() {
        for v := range output.OutChannel {
            logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
        }
    }()
    
    Scan("https://yarx.koalr.me/", nil)
    
    fmt.Println("wait ...")
    time.Sleep(5 * time.Second)
}
